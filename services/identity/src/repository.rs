//! PostgreSQL Repository for Identity Service

use async_trait::async_trait;

use kels_core::KeyEvent;
use kels_derive::SignedEvents;
use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime, StorageError, TransactionExecutor};
use verifiable_storage_postgres::{Order, PgPool, Query, QueryExecutor, Stored};

/// Maps KEL state to HSM key handles. Updated only on establishment events (icp, rot).
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[storable(table = "identity_hsm_key_bindings")]
pub struct HsmKeyBinding {
    #[said]
    pub said: cesr::Digest,
    #[prefix]
    pub prefix: cesr::Digest,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<cesr::Digest>,
    #[version]
    pub version: u64,
    pub kel_prefix: cesr::Digest,
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
        kel_prefix: &cesr::Digest,
    ) -> Result<Option<HsmKeyBinding>, StorageError> {
        let query = Query::<HsmKeyBinding>::for_table(Self::TABLE_NAME)
            .eq("kel_prefix", kel_prefix)
            .order_by("version", Order::Desc)
            .limit(1);
        self.pool.fetch_optional(query).await
    }

    pub async fn get_all_by_kel_prefix(
        &self,
        kel_prefix: &cesr::Digest,
    ) -> Result<Vec<HsmKeyBinding>, StorageError> {
        let query = Query::<HsmKeyBinding>::for_table(Self::TABLE_NAME)
            .eq("kel_prefix", kel_prefix)
            .order_by("version", Order::Asc);
        self.pool.fetch(query).await
    }
}

pub const AUTHORITY_IDENTITY_NAME: &str = "identity";

/// Maps a name to a KEL prefix and tracks last event SAID for continuity verification.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[storable(table = "identity_authority")]
pub struct AuthorityMapping {
    #[said]
    pub said: cesr::Digest,
    #[prefix]
    pub prefix: cesr::Digest,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<cesr::Digest>,
    #[version]
    pub version: u64,
    pub name: String,
    pub kel_prefix: cesr::Digest,
    pub last_said: cesr::Digest,
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
#[stored(item_type = KeyEvent, table = "identity_key_events", version_field = "serial")]
#[signed_events(
    signatures_table = "identity_key_event_signatures",
    recovery_table = "identity_recovery",
    archived_events_table = "identity_archived_events",
    archived_signatures_table = "identity_archived_event_signatures",
    recovery_events_table = "identity_recovery_events"
)]
pub struct KeyEventRepository {
    pub pool: PgPool,
}

impl KeyEventRepository {
    /// Begin a transaction with an advisory lock on a KEL prefix.
    /// Lock is held until the transaction is committed or rolled back.
    pub async fn begin_locked_transaction(
        &self,
        prefix: &cesr::Digest,
    ) -> Result<LockedKelTransaction, StorageError> {
        let mut tx = self.pool.begin_transaction().await?;
        tx.acquire_advisory_lock(prefix.as_ref()).await?;
        Ok(LockedKelTransaction {
            tx,
            prefix: prefix.clone(),
        })
    }
}

/// Transaction with advisory lock on a KEL prefix.
/// Reads from this transaction see a consistent snapshot under the lock.
pub struct LockedKelTransaction {
    tx: <PgPool as QueryExecutor>::Transaction,
    prefix: cesr::Digest,
}

impl LockedKelTransaction {
    /// Load a page of signed events within the locked transaction.
    pub async fn load(
        &mut self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<kels_core::SignedKeyEvent>, bool), StorageError> {
        kels_core::load_signed_history(
            &mut self.tx,
            KeyEventRepository::TABLE_NAME,
            KeyEventRepository::SIGNATURES_TABLE_NAME,
            self.prefix.as_ref(),
            limit,
            offset,
        )
        .await
        .map_err(|e| StorageError::StorageError(e.to_string()))
    }

    pub async fn commit(self) -> Result<(), StorageError> {
        self.tx.commit().await
    }
}

#[async_trait]
impl kels_core::PageLoader for LockedKelTransaction {
    async fn load_page(
        &mut self,
        _prefix: &cesr::Digest,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<kels_core::SignedKeyEvent>, bool), kels_core::KelsError> {
        self.load(limit, offset)
            .await
            .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))
    }
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
    use cesr::test_digest;

    use super::*;
    use ctor::dtor;
    use std::sync::OnceLock;
    use testcontainers::{ContainerAsync, core::ImageExt, runners::AsyncRunner};
    use testcontainers_modules::postgres::Postgres;
    use tokio::sync::OnceCell;
    use verifiable_storage::ChainedRepository;
    use verifiable_storage_postgres::RepositoryConnection;

    const TEST_CONTAINER_LABEL: (&str, &str) = ("kels-test", "true");

    #[dtor]
    fn cleanup_test_containers() {
        let _ = std::process::Command::new("docker")
            .args(["ps", "-q", "--filter", "label=kels-test=true"])
            .output()
            .map(|output| {
                let ids = String::from_utf8_lossy(&output.stdout);
                for id in ids.lines() {
                    let _ = std::process::Command::new("docker")
                        .args(["rm", "-f", id])
                        .output();
                }
            });
    }


    /// Shared test harness - initialized once, used by all tests.
    /// Cleaned up automatically at program exit via #[dtor].
    struct SharedHarness {
        database_url: String,
        _postgres: ContainerAsync<Postgres>,
    }

    /// Global shared harness
    static SHARED_HARNESS: OnceLock<OnceCell<Option<SharedHarness>>> = OnceLock::new();

    /// Get or initialize the shared test harness
    async fn get_harness() -> Option<&'static SharedHarness> {
        let cell = SHARED_HARNESS.get_or_init(OnceCell::new);
        let harness = cell
            .get_or_init(|| async {
                match SharedHarness::new().await {
                    Some(h) => Some(h),
                    None => {
                        eprintln!("WARNING: Failed to initialize shared test harness");
                        None
                    }
                }
            })
            .await;
        harness.as_ref()
    }

    impl SharedHarness {
        async fn new() -> Option<Self> {
            let postgres = match Postgres::default()
                .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
                .start()
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "WARNING: Skipping tests - Postgres container failed to start: {}",
                        e
                    );
                    return None;
                }
            };

            let pg_host = match postgres.get_host().await {
                Ok(h) => h,
                Err(e) => {
                    eprintln!(
                        "WARNING: Skipping tests - failed to get Postgres host: {}",
                        e
                    );
                    return None;
                }
            };

            // Retry port retrieval - testcontainers has a race where port may not be mapped yet
            let mut pg_port = None;
            for _ in 0..10 {
                match postgres.get_host_port_ipv4(5432).await {
                    Ok(port) => {
                        pg_port = Some(port);
                        break;
                    }
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
            let pg_port = match pg_port {
                Some(p) => p,
                None => {
                    eprintln!(
                        "WARNING: Skipping tests - failed to get Postgres port after retries"
                    );
                    return None;
                }
            };

            let database_url = format!(
                "postgres://postgres:postgres@{}:{}/postgres",
                pg_host, pg_port
            );

            // Initialize repository to run migrations
            let repo = match IdentityRepository::connect(&database_url).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "WARNING: Skipping tests - failed to connect to database: {}",
                        e
                    );
                    return None;
                }
            };

            if let Err(e) = repo.initialize().await {
                eprintln!("WARNING: Skipping tests - failed to run migrations: {}", e);
                return None;
            }

            eprintln!("Shared identity test database ready");

            Some(Self {
                database_url,
                _postgres: postgres,
            })
        }

        /// Create a fresh repository connection for this test
        async fn repo(&self) -> IdentityRepository {
            IdentityRepository::connect(&self.database_url)
                .await
                .expect("Failed to connect to shared database")
        }
    }

    #[test]
    fn test_authority_identity_name_constant() {
        assert_eq!(AUTHORITY_IDENTITY_NAME, "identity");
    }

    #[test]
    fn test_hsm_key_binding_struct() {
        let kel_prefix = test_digest("key-binding-kel-test-prefix");
        let binding = HsmKeyBinding {
            said: test_digest("key-binding-test-said"),
            prefix: test_digest("key-binding-test-prefix"),
            previous: None,
            version: 0,
            kel_prefix: kel_prefix.clone(),
            current_key_handle: "current_handle".to_string(),
            next_key_handle: "next_handle".to_string(),
            recovery_key_handle: "recovery_handle".to_string(),
            signing_generation: 1,
            recovery_generation: 0,
            created_at: StorageDatetime::now(),
        };

        assert_eq!(binding.kel_prefix, kel_prefix);
        assert_eq!(binding.version, 0);
        assert_eq!(binding.signing_generation, 1);
        assert_eq!(binding.recovery_generation, 0);
    }

    #[test]
    fn test_authority_mapping_struct() {
        let kel_prefix = test_digest("auth-mapping-kel");
        let mapping = AuthorityMapping {
            said: test_digest("auth-mapping-said"),
            prefix: test_digest("auth-mapping-prefix"),
            previous: None,
            version: 0,
            name: "auth_mapping_authority".to_string(),
            kel_prefix: kel_prefix.clone(),
            last_said: test_digest("auth-mapping-last-event-said"),
            created_at: StorageDatetime::now(),
        };

        assert_eq!(mapping.name, "auth_mapping_authority");
        assert_eq!(mapping.kel_prefix, kel_prefix);
    }

    #[test]
    fn test_hsm_key_binding_serialization_camel_case() {
        let binding = HsmKeyBinding {
            said: test_digest("ser-said"),
            prefix: test_digest("ser-prefix"),
            previous: None,
            version: 0,
            kel_prefix: test_digest("ser-kel"),
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
            said: test_digest("ser-auth"),
            prefix: test_digest("ser-auth-prefix"),
            previous: None,
            version: 0,
            name: "ser_authority".to_string(),
            kel_prefix: test_digest("ser-auth-kel"),
            last_said: test_digest("ser-last"),
            created_at: StorageDatetime::now(),
        };

        let json = serde_json::to_string(&mapping).expect("Serialization failed");
        assert!(json.contains("kelPrefix"));
        assert!(json.contains("lastSaid"));
        assert!(json.contains("createdAt"));
    }

    #[tokio::test]
    async fn test_hsm_binding_get_latest_by_kel_prefix_empty() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let result = repo
            .hsm_bindings
            .get_latest_by_kel_prefix(&test_digest("nonexistent-prefix-empty"))
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_hsm_binding_store_and_retrieve() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let kel_prefix = test_digest("hsm-store-kel");
        let cur = test_digest("hsm-store-cur").to_string();
        let nxt = test_digest("hsm-store-nxt").to_string();
        let rec = test_digest("hsm-store-rec").to_string();

        let binding =
            HsmKeyBinding::create(kel_prefix.clone(), cur.clone(), nxt, rec, 0, 0).unwrap();

        repo.hsm_bindings
            .insert(binding.clone())
            .await
            .expect("Failed to store binding");

        let retrieved = repo
            .hsm_bindings
            .get_latest_by_kel_prefix(&kel_prefix)
            .await
            .expect("Query failed")
            .expect("Binding not found");

        assert_eq!(retrieved.kel_prefix, kel_prefix);
        assert_eq!(retrieved.current_key_handle, cur);
        assert_eq!(retrieved.version, 0);
    }

    #[tokio::test]
    async fn test_hsm_binding_returns_latest_version() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let kel_prefix = test_digest("hsm-ver-kel");
        let cur_v0 = test_digest("hsm-ver-cur-v0").to_string();
        let nxt_v0 = test_digest("hsm-ver-nxt-v0").to_string();
        let rec_v0 = test_digest("hsm-ver-rec-v0").to_string();
        let cur_v1 = test_digest("hsm-ver-cur-v1").to_string();
        let nxt_v1 = test_digest("hsm-ver-nxt-v1").to_string();

        let binding_v0 =
            HsmKeyBinding::create(kel_prefix.clone(), cur_v0, nxt_v0, rec_v0, 0, 0).unwrap();

        repo.hsm_bindings
            .insert(binding_v0.clone())
            .await
            .expect("Failed to store v0");

        let mut binding_v1 = binding_v0.clone();
        binding_v1.current_key_handle = cur_v1.clone();
        binding_v1.next_key_handle = nxt_v1;
        binding_v1.signing_generation = 1;

        repo.hsm_bindings
            .update(binding_v1)
            .await
            .expect("Failed to store v1");

        let retrieved = repo
            .hsm_bindings
            .get_latest_by_kel_prefix(&kel_prefix)
            .await
            .expect("Query failed")
            .expect("Binding not found");

        assert!(retrieved.version >= 1);
        assert_eq!(retrieved.current_key_handle, cur_v1);
        assert_eq!(retrieved.signing_generation, 1);
    }

    #[tokio::test]
    async fn test_authority_get_by_name_empty() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let result = repo
            .authority
            .get_by_name("nonexistent_authority")
            .await
            .expect("Query failed");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_authority_store_and_retrieve() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let name = "auth_store_test";
        let kel_prefix = test_digest("auth-store-kel");
        let last_said = test_digest("auth-store-last");

        let mapping =
            AuthorityMapping::create(name.to_string(), kel_prefix.clone(), last_said.clone())
                .unwrap();

        repo.authority
            .insert(mapping.clone())
            .await
            .expect("Failed to store mapping");

        let retrieved = repo
            .authority
            .get_by_name(name)
            .await
            .expect("Query failed")
            .expect("Mapping not found");

        assert_eq!(retrieved.name, name);
        assert_eq!(retrieved.kel_prefix, kel_prefix);
        assert_eq!(retrieved.last_said, last_said);
    }

    #[tokio::test]
    async fn test_authority_returns_latest_version() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let name = "auth_versioned_test";
        let kel_prefix_v0 = test_digest("auth-ver-kel-v0");
        let last_said_v0 = test_digest("auth-ver-last-v0");
        let kel_prefix_v1 = test_digest("auth-ver-kel-v1");
        let last_said_v1 = test_digest("auth-ver-last-v1");

        let mapping_v0 = AuthorityMapping::create(
            name.to_string(),
            kel_prefix_v0.clone(),
            last_said_v0.clone(),
        )
        .unwrap();

        repo.authority
            .insert(mapping_v0.clone())
            .await
            .expect("Failed to store v0");

        let mut mapping_v1 = mapping_v0.clone();
        mapping_v1.kel_prefix = kel_prefix_v1.clone();
        mapping_v1.last_said = last_said_v1.clone();

        repo.authority
            .update(mapping_v1)
            .await
            .expect("Failed to store v1");

        let retrieved = repo
            .authority
            .get_by_name(name)
            .await
            .expect("Query failed")
            .expect("Mapping not found");

        assert!(retrieved.version >= 1);
        assert_eq!(retrieved.kel_prefix, kel_prefix_v1);
        assert_eq!(retrieved.last_said, last_said_v1);
    }
}
