//! PostgreSQL Repository for Identity Service

use async_trait::async_trait;

use kels_core::{IdentityEvent, KeyEvent, SadEvent};
use kels_derive::SignedEvents;
use serde::{Deserialize, Serialize};
use cesr::Matter;
use verifiable_storage::{
    CorrelatedSubquery, Filter, SelfAddressed, StorageDatetime, StorageError, TransactionExecutor,
    UnchainedRepository, Value,
};
use verifiable_storage_postgres::{Order, PgPool, Query, QueryExecutor, Stored};

/// Maps KEL state to HSM key handles. Updated only on establishment events (icp, rot).
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[storable(table = "identity_hsm_key_bindings")]
pub struct HsmKeyBinding {
    #[said]
    pub said: cesr::Digest256,
    #[prefix]
    pub prefix: cesr::Digest256,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<cesr::Digest256>,
    #[version]
    pub version: u64,
    pub kel_prefix: cesr::Digest256,
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
        kel_prefix: &cesr::Digest256,
    ) -> Result<Option<HsmKeyBinding>, StorageError> {
        let query = Query::<HsmKeyBinding>::for_table(Self::TABLE_NAME)
            .eq("kel_prefix", kel_prefix)
            .order_by("version", Order::Desc)
            .limit(1);
        self.pool.fetch_optional(query).await
    }

    pub async fn get_all_by_kel_prefix(
        &self,
        kel_prefix: &cesr::Digest256,
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
    pub said: cesr::Digest256,
    #[prefix]
    pub prefix: cesr::Digest256,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<cesr::Digest256>,
    #[version]
    pub version: u64,
    pub name: String,
    pub kel_prefix: cesr::Digest256,
    pub last_said: cesr::Digest256,
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
        prefix: &cesr::Digest256,
    ) -> Result<LockedKelTransaction, StorageError> {
        let mut tx = self.pool.begin_transaction().await?;
        tx.acquire_advisory_lock(prefix.as_ref()).await?;
        Ok(LockedKelTransaction {
            tx,
            prefix: *prefix,
        })
    }
}

/// Transaction with advisory lock on a KEL prefix.
/// Reads from this transaction see a consistent snapshot under the lock.
pub struct LockedKelTransaction {
    tx: <PgPool as QueryExecutor>::Transaction,
    prefix: cesr::Digest256,
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
            &self.prefix,
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
        _prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<kels_core::SignedKeyEvent>, bool), kels_core::KelsError> {
        self.load(limit, offset)
            .await
            .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))
    }
}

/// Local IEL events — the node's own IEL chain. Identity is the source of
/// truth; sadstore holds the infrastructure-distributed copy. Single-author
/// chain; divergence is impossible by construction (the identity service is
/// the sole author of its own IEL), but if it ever happens it's contested
/// per the project-wide rule.
#[derive(Stored)]
#[stored(item_type = IdentityEvent, table = "identity_iel_events", chained = true)]
pub struct IelRepository {
    pub pool: PgPool,
}

impl IelRepository {
    /// Fetch all events for an IEL prefix, ordered by version ascending.
    pub async fn fetch_chain(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Vec<IdentityEvent>, StorageError> {
        let query = Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .order_by("version", Order::Asc);
        self.pool.fetch(query).await
    }

    /// Fetch the tip event for an IEL prefix.
    pub async fn fetch_tip(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<IdentityEvent>, StorageError> {
        let query = Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .order_by("version", Order::Desc)
            .limit(1);
        self.pool.fetch_optional(query).await
    }

    /// Effective SAID for a chain prefix.
    ///
    /// Fast sync-decision lookup (single SQL query). Finds tip events via a
    /// NOT EXISTS subquery — events at this prefix that no other event
    /// supersedes (`previous = this.said`). Mirrors the KEL-side
    /// `compute_prefix_effective_said` pattern.
    ///
    /// - 0 tips → `None` (chain absent locally; first-boot path).
    /// - 1 tip → tip's SAID (linear chain).
    /// - More than 1 tip → `hash_effective_said("contested:{prefix}")` per project-wide rule that divergence ≡ contested for identity-authored IELs.
    ///
    /// Use this for sync decisions ("do I already have this chain?"), not
    /// trust decisions (which require a verified-walk through the chain).
    pub async fn effective_said(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<cesr::Digest256>, StorageError> {
        let query = Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix.as_ref())
            .not_exists(CorrelatedSubquery::new(
                Self::TABLE_NAME,
                "_cs",
                Self::TABLE_NAME,
                vec![("previous".to_string(), "said".to_string())],
                vec![Filter::Eq(
                    "_cs.prefix".to_string(),
                    Value::String(prefix.qb64()),
                )],
            ))
            .order_by("said", Order::Asc);

        let tips: Vec<IdentityEvent> = self.pool.fetch(query).await?;
        match tips.as_slice() {
            [] => Ok(None),
            [tip] => Ok(Some(tip.said)),
            _ => Ok(Some(kels_core::hash_effective_said(&format!(
                "contested:{prefix}"
            )))),
        }
    }
}

/// Local SEL events — the node's own SEL chains (address SEL, and any future
/// identity-owned SEL types). Identity is the source of truth; sadstore holds
/// the infrastructure-distributed copy. Single-author per chain prefix here,
/// so no divergence/repair/contest handling.
///
/// Stores `kels_core::SadEvent` items (legacy type name — the *chain* is a SEL
/// per `feedback_sel_vs_sad_language`).
#[derive(Stored)]
#[stored(item_type = SadEvent, table = "identity_sel_events", chained = true)]
pub struct SelRepository {
    pub pool: PgPool,
}

impl SelRepository {
    /// Fetch all events for a SEL prefix, ordered by version ascending.
    pub async fn fetch_chain(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Vec<SadEvent>, StorageError> {
        let query = Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .order_by("version", Order::Asc);
        self.pool.fetch(query).await
    }

    /// Fetch the tip event for a SEL prefix.
    pub async fn fetch_tip(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<SadEvent>, StorageError> {
        let query = Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .order_by("version", Order::Desc)
            .limit(1);
        self.pool.fetch_optional(query).await
    }

    /// Effective SAID for a chain prefix. Same shape as
    /// [`IelRepository::effective_said`] — see that doc-comment.
    pub async fn effective_said(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<cesr::Digest256>, StorageError> {
        let query = Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix.as_ref())
            .not_exists(CorrelatedSubquery::new(
                Self::TABLE_NAME,
                "_cs",
                Self::TABLE_NAME,
                vec![("previous".to_string(), "said".to_string())],
                vec![Filter::Eq(
                    "_cs.prefix".to_string(),
                    Value::String(prefix.qb64()),
                )],
            ))
            .order_by("said", Order::Asc);

        let tips: Vec<SadEvent> = self.pool.fetch(query).await?;
        match tips.as_slice() {
            [] => Ok(None),
            [tip] => Ok(Some(tip.said)),
            _ => Ok(Some(kels_core::hash_effective_said(&format!(
                "contested:{prefix}"
            )))),
        }
    }
}

/// Cache entry for a SAD body the node authored or fetched. The entry's
/// `said` is derived from `(object_said, object)` via `SelfAddressed`;
/// `object_said` is the contained SAD's own SAID and is what consumers look
/// up by. Identical objects produce identical entries, so write-once-by-said
/// is idempotent.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
#[storable(table = "identity_sad_objects")]
pub struct SadObjectEntry {
    #[said]
    pub said: cesr::Digest256,
    pub object_said: cesr::Digest256,
    pub object: serde_json::Value,
}

/// Local SAD-body cache — layer 0 of identity's CascadingSadStore. Holds the
/// SAD bodies the node authored, plus any remote bodies cached on a previous
/// fetch. Lookup is by `object_said` (the SAD's own SAID); the entry's own
/// SAID is internal bookkeeping.
#[derive(Stored)]
#[stored(item_type = SadObjectEntry, table = "identity_sad_objects", chained = false)]
pub struct SadObjectRepository {
    pub pool: PgPool,
}

impl SadObjectRepository {
    /// Idempotent store: insert if absent; treat duplicates as success
    /// (same content → same entry SAID → already present).
    pub async fn store(&self, entry: SadObjectEntry) -> Result<(), StorageError> {
        match self.insert(entry).await {
            Ok(_) => Ok(()),
            Err(StorageError::DuplicateRecord(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Fetch a cached entry by the contained SAD's SAID.
    pub async fn get_by_object_said(
        &self,
        object_said: &cesr::Digest256,
    ) -> Result<Option<SadObjectEntry>, StorageError> {
        let query = Query::<SadObjectEntry>::for_table(Self::TABLE_NAME)
            .eq("object_said", object_said)
            .limit(1);
        self.pool.fetch_optional(query).await
    }

    /// List cached object SAIDs in ascending order, paginated.
    ///
    /// Returns `(saids, has_more)`. `since` is exclusive; pass the last item
    /// of the previous page to advance. Mirrors `SadStore::list`'s shape.
    pub async fn list_object_saids(
        &self,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<cesr::Digest256>, bool), StorageError> {
        let mut query = Query::<SadObjectEntry>::for_table(Self::TABLE_NAME)
            .order_by("object_said", Order::Asc)
            .limit((limit + 1) as u64);
        if let Some(cursor) = since {
            query = query.gt("object_said", cursor);
        }
        let mut rows: Vec<SadObjectEntry> = self.pool.fetch(query).await?;
        let has_more = rows.len() > limit;
        if has_more {
            rows.truncate(limit);
        }
        Ok((rows.into_iter().map(|e| e.object_said).collect(), has_more))
    }

    /// Delete by the contained SAD's SAID. No-op if absent.
    pub async fn delete_by_object_said(
        &self,
        object_said: &cesr::Digest256,
    ) -> Result<(), StorageError> {
        let delete = verifiable_storage::Delete::<SadObjectEntry>::for_table(Self::TABLE_NAME)
            .eq("object_said", object_said);
        self.pool.delete(delete).await?;
        Ok(())
    }
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct IdentityRepository {
    pub hsm_bindings: HsmBindingRepository,
    pub authority: AuthorityRepository,
    pub kel: KeyEventRepository,
    pub iel: IelRepository,
    pub sel: SelRepository,
    pub sad_objects: SadObjectRepository,
}

#[cfg(test)]
pub(crate) mod tests {
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
    pub(crate) struct SharedHarness {
        database_url: String,
        _postgres: ContainerAsync<Postgres>,
    }

    /// Global shared harness
    static SHARED_HARNESS: OnceLock<OnceCell<Option<SharedHarness>>> = OnceLock::new();

    /// Get or initialize the shared test harness
    pub(crate) async fn get_harness() -> Option<&'static SharedHarness> {
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
        pub(crate) async fn repo(&self) -> IdentityRepository {
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
            kel_prefix,
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
            kel_prefix,
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

        let binding = HsmKeyBinding::create(kel_prefix, cur.clone(), nxt, rec, 0, 0).unwrap();

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

        let binding_v0 = HsmKeyBinding::create(kel_prefix, cur_v0, nxt_v0, rec_v0, 0, 0).unwrap();

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

        let mapping = AuthorityMapping::create(name.to_string(), kel_prefix, last_said).unwrap();

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

        let mapping_v0 =
            AuthorityMapping::create(name.to_string(), kel_prefix_v0, last_said_v0).unwrap();

        repo.authority
            .insert(mapping_v0.clone())
            .await
            .expect("Failed to store v0");

        let mut mapping_v1 = mapping_v0.clone();
        mapping_v1.kel_prefix = kel_prefix_v1;
        mapping_v1.last_said = last_said_v1;

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

    // ==================== IEL repository ====================

    #[tokio::test]
    async fn test_iel_fetch_chain_empty_when_no_events() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let chain = repo
            .iel
            .fetch_chain(&test_digest("iel-empty-prefix"))
            .await
            .expect("fetch_chain returns empty Vec on unknown prefix");
        assert!(chain.is_empty());
    }

    #[tokio::test]
    async fn test_iel_fetch_tip_none_when_no_events() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let tip = repo
            .iel
            .fetch_tip(&test_digest("iel-no-tip-prefix"))
            .await
            .expect("fetch_tip returns Ok(None) on unknown prefix");
        assert!(tip.is_none());
    }

    #[tokio::test]
    async fn test_iel_round_trip_single_icp() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let auth_policy = test_digest("iel-rt-auth");
        let governance_policy = test_digest("iel-rt-gov");
        let icp =
            IdentityEvent::icp(auth_policy, governance_policy, "kels/iel/v1/test/icp-only").unwrap();

        repo.iel.insert(icp.clone()).await.expect("insert Icp");

        let tip = repo.iel.fetch_tip(&icp.prefix).await.unwrap().unwrap();
        assert_eq!(tip.said, icp.said);
        assert_eq!(tip.version, 0);

        let chain = repo.iel.fetch_chain(&icp.prefix).await.unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].said, icp.said);
    }

    #[tokio::test]
    async fn test_iel_fetch_chain_ordered_by_version_ascending() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let auth = test_digest("iel-ord-auth");
        let gov = test_digest("iel-ord-gov");
        let icp = IdentityEvent::icp(auth, gov, "kels/iel/v1/test/ordering").unwrap();
        let evl = IdentityEvent::evl(&icp, None, None).unwrap();
        let cnt = IdentityEvent::cnt(&evl).unwrap();

        // Insert in non-version order to confirm fetch_chain sorts.
        repo.iel.insert(evl.clone()).await.expect("insert Evl");
        repo.iel.insert(cnt.clone()).await.expect("insert Cnt");
        repo.iel.insert(icp.clone()).await.expect("insert Icp");

        let chain = repo.iel.fetch_chain(&icp.prefix).await.unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].said, icp.said);
        assert_eq!(chain[1].said, evl.said);
        assert_eq!(chain[2].said, cnt.said);

        // Tip is the highest-version event.
        let tip = repo.iel.fetch_tip(&icp.prefix).await.unwrap().unwrap();
        assert_eq!(tip.said, cnt.said);
        assert_eq!(tip.version, 2);
    }

    // ==================== SEL repository ====================

    #[tokio::test]
    async fn test_sel_fetch_chain_empty_when_no_events() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let chain = repo
            .sel
            .fetch_chain(&test_digest("sel-empty-prefix"))
            .await
            .expect("fetch_chain returns empty Vec on unknown prefix");
        assert!(chain.is_empty());
    }

    // ==================== SAD object repository ====================

    fn sample_sad_body(label: &str) -> (cesr::Digest256, serde_json::Value) {
        let object_said = test_digest(label);
        let body = serde_json::json!({"said": object_said, "label": label});
        (object_said, body)
    }

    #[tokio::test]
    async fn test_sad_objects_store_and_get_by_object_said() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let (object_said, body) = sample_sad_body("sad-store-roundtrip");
        let entry = SadObjectEntry::create(object_said, body.clone()).unwrap();
        repo.sad_objects.store(entry).await.expect("store");

        let fetched = repo
            .sad_objects
            .get_by_object_said(&object_said)
            .await
            .expect("get")
            .expect("entry present");
        assert_eq!(fetched.object_said, object_said);
        assert_eq!(fetched.object, body);
    }

    #[tokio::test]
    async fn test_sad_objects_store_is_idempotent() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let (object_said, body) = sample_sad_body("sad-idempotent");
        let entry = SadObjectEntry::create(object_said, body).unwrap();
        // Two calls with the same entry must not error — the second is a
        // no-op (same SAID → same row).
        repo.sad_objects.store(entry.clone()).await.expect("first store");
        repo.sad_objects.store(entry).await.expect("second store");
    }

    #[tokio::test]
    async fn test_sad_objects_get_missing_returns_none() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;
        let result = repo
            .sad_objects
            .get_by_object_said(&test_digest("missing-sad"))
            .await
            .expect("query");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_sad_objects_list_paginates() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let mut object_saids = Vec::new();
        for i in 0..3 {
            let (object_said, body) = sample_sad_body(&format!("sad-paging-{i}"));
            object_saids.push(object_said);
            let entry = SadObjectEntry::create(object_said, body).unwrap();
            repo.sad_objects.store(entry).await.unwrap();
        }
        object_saids.sort();

        let (page1, has_more) = repo.sad_objects.list_object_saids(None, 2).await.unwrap();
        // Other tests share the schema; the list may contain entries beyond
        // the three we just inserted. Verify the first page is the requested
        // size and that the cursor advance is well-formed.
        assert_eq!(page1.len(), 2);
        // `has_more` is true if the DB has more than 2 entries total.
        assert!(has_more || page1.len() == 2);

        let cursor = page1.last().expect("page1 non-empty");
        let (page2, _) = repo
            .sad_objects
            .list_object_saids(Some(cursor), 2)
            .await
            .unwrap();
        // All entries on page2 are strictly greater than the cursor.
        for said in &page2 {
            assert!(said > cursor, "cursor advance must be exclusive");
        }
    }

    #[tokio::test]
    async fn test_sad_objects_delete() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let (object_said, body) = sample_sad_body("sad-delete");
        let entry = SadObjectEntry::create(object_said, body).unwrap();
        repo.sad_objects.store(entry).await.unwrap();

        repo.sad_objects
            .delete_by_object_said(&object_said)
            .await
            .unwrap();
        assert!(
            repo.sad_objects
                .get_by_object_said(&object_said)
                .await
                .unwrap()
                .is_none()
        );

        // Delete-missing is a no-op.
        repo.sad_objects
            .delete_by_object_said(&test_digest("never-stored"))
            .await
            .expect("delete missing is fine");
    }

    #[tokio::test]
    async fn test_sel_round_trip_inception_batch() {
        let Some(harness) = get_harness().await else {
            return;
        };
        let repo = harness.repo().await;

        let identity_prefix = test_digest("sel-rt-identity");
        let icp =
            kels_core::SadEvent::icp(identity_prefix, kels_core::PEER_SERVICES_SEL_TOPIC).unwrap();
        let iel_event = test_digest("sel-rt-iel-event");
        let content = test_digest("sel-rt-address-sad");
        let upd = kels_core::SadEvent::upd(&icp, iel_event, content).unwrap();
        let sea = kels_core::SadEvent::sea(&upd, iel_event).unwrap();

        repo.sel.insert(icp.clone()).await.expect("insert Icp");
        repo.sel.insert(upd.clone()).await.expect("insert Upd");
        repo.sel.insert(sea.clone()).await.expect("insert Sea");

        let chain = repo.sel.fetch_chain(&icp.prefix).await.unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].said, icp.said);
        assert_eq!(chain[1].said, upd.said);
        assert_eq!(chain[2].said, sea.said);

        let tip = repo.sel.fetch_tip(&icp.prefix).await.unwrap().unwrap();
        assert_eq!(tip.said, sea.said);
        assert_eq!(tip.kind, kels_core::SadEventKind::Sea);
        // Sea preserves the Upd's content (the address-SAD SAID), which is the
        // address-resolution payload the discovery walker reads.
        assert_eq!(tip.content, Some(content));
    }
}
