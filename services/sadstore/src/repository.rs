//! PostgreSQL Repository for KELS SADStore

use std::collections::HashSet;

use kels_core::{Custody, SadPointer, SadPointerRepair, SadPointerRepairRecord};
use kels_policy::Policy;
use verifiable_storage::{
    ChainedRepository, ColumnQuery, QueryExecutor, StorageError, TransactionExecutor,
    UnchainedRepository, Value,
};
use verifiable_storage_postgres::{Filter, PgPool, Stored};

/// Result of a `save_batch` operation on a pointer chain.
#[derive(Debug)]
pub enum SaveBatchResult {
    /// Records were accepted, chain remains non-divergent.
    Accepted { new_count: u32 },
    /// A version collision was detected — the forking record was inserted and
    /// the chain is now divergent (frozen). Remaining batch records were discarded.
    DivergenceCreated {
        new_count: u32,
        diverged_at_version: u64,
    },
}

#[derive(Stored)]
#[stored(item_type = SadPointer, table = "sad_pointers", chained = true)]
pub struct SadPointerRepository {
    pub pool: PgPool,
}

impl SadPointerRepository {
    /// Store a batch of pointer records within a caller-managed transaction.
    ///
    /// Caller must hold an advisory lock on the chain prefix.
    ///
    /// If the chain is already divergent, returns an error. If a record in the
    /// batch collides at the same version as an existing record (creating
    /// divergence), inserts only up to and including the forking record, then
    /// discards the rest. The chain freezes immediately.
    pub async fn save_batch<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        records: &[SadPointer],
    ) -> Result<SaveBatchResult, StorageError> {
        if records.is_empty() {
            return Ok(SaveBatchResult::Accepted { new_count: 0 });
        }

        let prefix = records[0].prefix;

        // Quick divergence check — reject appends to frozen chains
        let divergence_query = ColumnQuery::new(Self::TABLE_NAME, "*")
            .filter(Filter::Eq(
                "prefix".to_string(),
                Value::String(prefix.to_string()),
            ))
            .group_by("version")
            .limit(1);
        let counts: Vec<i64> = tx.fetch_grouped_count(divergence_query).await?;
        if counts.first().is_some_and(|&c| c > 1) {
            return Err(StorageError::StorageError(
                "Chain is divergent — repair required".to_string(),
            ));
        }

        // Collect existing SAIDs for dedup
        let existing_saids: HashSet<cesr::Digest256> = {
            let saids: Vec<String> = records.iter().map(|r| r.said.to_string()).collect();
            let query =
                verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                    .r#in("said", saids);
            tx.fetch(query)
                .await?
                .into_iter()
                .map(|r: SadPointer| r.said)
                .collect()
        };

        // Collect occupied versions in one query: fetch only the version column
        // for existing records at the batch's versions.
        let mut occupied_versions: HashSet<u64> = {
            let batch_versions: Vec<i64> = records
                .iter()
                .map(|r| r.version as i64)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let query = ColumnQuery::new(Self::TABLE_NAME, "version")
                .eq("prefix", &prefix)
                .r#in("version", batch_versions);
            tx.fetch_column_i64(query)
                .await?
                .into_iter()
                .map(|v| v as u64)
                .collect()
        };

        let mut count = 0u32;
        for record in records {
            if existing_saids.contains(&record.said) {
                continue;
            }

            // Version collision creates divergence — insert this forking record then freeze
            if occupied_versions.contains(&record.version) {
                self.insert_in(tx, record.clone()).await?;
                count += 1;
                return Ok(SaveBatchResult::DivergenceCreated {
                    new_count: count,
                    diverged_at_version: record.version,
                });
            }

            self.insert_in(tx, record.clone()).await?;
            occupied_versions.insert(record.version);
            count += 1;
        }

        Ok(SaveBatchResult::Accepted { new_count: count })
    }

    /// Truncate records at and after the first replacement's version and insert replacements.
    ///
    /// Used to repair divergent chains. Archives displaced records, creates a repair
    /// audit record, then inserts the replacements.
    /// Caller must hold an advisory lock on the chain prefix.
    pub async fn truncate_and_replace<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        records: &[SadPointer],
    ) -> Result<u64, StorageError> {
        if records.is_empty() {
            return Err(StorageError::StorageError("Empty batch".to_string()));
        }

        let prefix = records[0].prefix;

        // Note: no write_policy consistency check here — write_policy can evolve across
        // versions, so repair records at v3+ may legitimately differ from v0's write_policy.
        // Callers must verify policy satisfaction independently (the handler does this via
        // SadChainVerifier + PolicyChecker after truncate_and_replace).

        // Skip leading records that already exist locally
        let (new_records, from_version) = {
            let saids: Vec<String> = records.iter().map(|r| r.said.to_string()).collect();
            let existing_query =
                verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                    .r#in("said", saids);
            let existing: HashSet<cesr::Digest256> = tx
                .fetch(existing_query)
                .await?
                .into_iter()
                .map(|r: SadPointer| r.said)
                .collect();
            let deduped: Vec<_> = records
                .iter()
                .skip_while(|r| existing.contains(&r.said))
                .collect();
            if deduped.is_empty() {
                let last_version = records.last().map(|r| r.version).unwrap_or(0);
                (deduped, last_version + 1)
            } else {
                let version = deduped[0].version;
                (deduped, version)
            }
        };

        // Archive records page-at-a-time before deleting
        let page_size = kels_core::page_size();
        let mut repair_said: Option<cesr::Digest256> = None;
        let mut version_cursor = from_version;

        loop {
            let page_query =
                verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                    .eq("prefix", &prefix)
                    .gte("version", version_cursor)
                    .order_by("version", verifiable_storage::Order::Asc)
                    .limit(page_size as u64);
            let page: Vec<SadPointer> = tx.fetch(page_query).await?;

            if page.is_empty() {
                break;
            }

            let repair_said_ref = match &repair_said {
                Some(said) => said,
                None => {
                    let repair = SadPointerRepair::create(prefix, from_version)?;
                    tx.insert(&repair).await?;
                    repair_said = Some(repair.said);
                    repair_said.as_ref().ok_or_else(|| {
                        StorageError::StorageError("repair SAID missing".to_string())
                    })?
                }
            };

            // Skip records already in archives (stale gossip can re-insert fork
            // records after a prior repair archived them)
            let already_archived: HashSet<cesr::Digest256> = {
                let page_saids: Vec<String> = page.iter().map(|r| r.said.to_string()).collect();
                let archive_query = verifiable_storage_postgres::Query::<SadPointer>::for_table(
                    Self::ARCHIVED_RECORDS_TABLE,
                )
                .r#in("said", page_saids);
                tx.fetch(archive_query)
                    .await?
                    .into_iter()
                    .map(|r: SadPointer| r.said)
                    .collect()
            };

            for record in &page {
                if already_archived.contains(&record.said) {
                    continue;
                }
                tx.insert_with_table(record, Self::ARCHIVED_RECORDS_TABLE)
                    .await?;
                let repair_record = SadPointerRepairRecord::create(*repair_said_ref, record.said)?;
                tx.insert(&repair_record).await?;
            }

            let page_len = page.len();
            if let Some(last) = page.last() {
                version_cursor = last.version + 1;
            }
            if page_len < page_size {
                break;
            }
        }

        // Delete records at and after from_version
        let delete_records = verifiable_storage::Delete::<SadPointer>::for_table(Self::TABLE_NAME)
            .eq("prefix", &prefix)
            .gte("version", from_version);
        tx.delete(delete_records).await?;

        // Insert replacements
        for record in new_records {
            self.insert_in(tx, record.clone()).await?;
        }

        Ok(from_version)
    }

    /// Quick check: does any version appear more than once for this prefix?
    pub async fn is_divergent(&self, prefix: &cesr::Digest256) -> Result<bool, StorageError> {
        let query = ColumnQuery::new(Self::TABLE_NAME, "*")
            .filter(Filter::Eq(
                "prefix".to_string(),
                Value::String(prefix.to_string()),
            ))
            .group_by("version")
            .limit(1);
        let counts: Vec<i64> = self.pool.fetch_grouped_count(query).await?;
        Ok(counts.first().is_some_and(|&c| c > 1))
    }

    /// Check if a pointer with the given SAID exists.
    pub async fn exists(&self, said: &cesr::Digest256) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
            .eq("said", said.as_ref())
            .limit(1);
        Ok(!self.pool.fetch(query).await?.is_empty())
    }

    /// Get the chain as bare `SadPointer`s.
    ///
    /// Ordering: `version ASC, said ASC` — deterministic across nodes.
    /// Delegates to `get_stored_in` via an implicit transaction.
    pub async fn get_stored(
        &self,
        prefix: &str,
        since_said: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Vec<SadPointer>, StorageError> {
        let mut tx = self.pool.begin_transaction().await?;
        let result = self
            .get_stored_in(&mut tx, prefix, since_said, limit)
            .await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Get chain records within an existing transaction.
    ///
    /// Same ordering as `get_stored`: `version ASC, said ASC`.
    pub async fn get_stored_in<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        prefix: &str,
        since_said: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Vec<SadPointer>, StorageError> {
        let since_position: Option<(u64, cesr::Digest256)> = if let Some(said) = since_said {
            let cursor_query =
                verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                    .eq("said", said)
                    .limit(1);
            tx.fetch(cursor_query)
                .await?
                .into_iter()
                .next()
                .map(|r| (r.version, r.said))
        } else {
            None
        };

        let mut query =
            verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                .eq("prefix", prefix)
                .order_by("version", verifiable_storage_postgres::Order::Asc)
                .order_by("said", verifiable_storage_postgres::Order::Asc);

        if let Some((version, _)) = &since_position {
            query = query.gte("version", *version);
        }

        if let Some(limit) = limit {
            let fetch_limit = if since_position.is_some() {
                limit + 2
            } else {
                limit
            };
            query = query.limit(fetch_limit);
        }

        let mut records: Vec<SadPointer> = tx.fetch(query).await?;

        if let Some((version, said)) = &since_position {
            let skipped = records.len();
            records.retain(|r| r.version > *version || (r.version == *version && r.said > *said));
            let skipped = skipped - records.len();

            if skipped > 2 {
                return Err(StorageError::StorageError(format!(
                    "Chain integrity violation: {} records skipped at version {} for prefix {} — possible DB tampering",
                    skipped, version, prefix
                )));
            }

            if let Some(limit) = limit {
                records.truncate(limit as usize);
            }
        }

        Ok(records)
    }

    /// Get the effective SAID for a chain prefix.
    pub async fn effective_said(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<(cesr::Digest256, bool)>, StorageError> {
        let latest = self.get_latest(prefix).await?;
        let Some(latest) = latest else {
            return Ok(None);
        };

        if self.is_divergent(prefix).await? {
            let said = kels_core::hash_effective_said(&format!("divergent:{}", prefix));
            return Ok(Some((said, true)));
        }

        Ok(Some((latest.said, false)))
    }

    const ARCHIVED_RECORDS_TABLE: &'static str = "sad_pointer_archives";

    /// Get repairs for a chain prefix, paginated.
    pub async fn get_repairs(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<kels_core::SadPointerRepair>, bool), StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<kels_core::SadPointerRepair>::new()
            .eq("pointer_prefix", prefix)
            .order_by("repaired_at", verifiable_storage_postgres::Order::Asc)
            .offset(offset)
            .limit(limit + 1);
        let mut repairs: Vec<kels_core::SadPointerRepair> = self.pool.fetch(query).await?;

        let has_more = repairs.len() as u64 > limit;
        repairs.truncate(limit as usize);
        Ok((repairs, has_more))
    }

    /// Get archived records for a specific repair, paginated.
    pub async fn get_repair_records(
        &self,
        repair_said: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SadPointer>, bool), StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let link_query = verifiable_storage_postgres::Query::<SadPointerRepairRecord>::new()
            .eq("repair_said", repair_said)
            .offset(offset)
            .limit(limit + 1);
        let mut links: Vec<SadPointerRepairRecord> = self.pool.fetch(link_query).await?;

        let has_more = links.len() as u64 > limit;
        links.truncate(limit as usize);

        if links.is_empty() {
            return Ok((Vec::new(), false));
        }

        let pointer_saids: Vec<String> = links.iter().map(|l| l.pointer_said.to_string()).collect();

        let records_query = verifiable_storage_postgres::Query::<SadPointer>::for_table(
            Self::ARCHIVED_RECORDS_TABLE,
        )
        .r#in("said", pointer_saids);
        let records: Vec<SadPointer> = self.pool.fetch(records_query).await?;

        Ok((records, has_more))
    }

    /// List chain prefixes with their effective SAIDs, paginated.
    pub async fn list_prefixes(
        &self,
        cursor: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<kels_core::PrefixListResponse, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let mut query =
            verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                .distinct_on("prefix")
                .order_by("prefix", verifiable_storage_postgres::Order::Asc)
                .order_by("version", verifiable_storage_postgres::Order::Desc)
                .limit(limit as u64 + 1);

        if let Some(cursor) = cursor {
            query = query.gt("prefix", cursor.as_ref());
        }

        let records: Vec<SadPointer> = self.pool.fetch(query).await?;

        let mut prefix_states: Vec<kels_core::PrefixState> = records
            .into_iter()
            .map(|r| kels_core::PrefixState {
                prefix: r.prefix,
                said: r.said,
            })
            .collect();

        let next_cursor = if prefix_states.len() > limit {
            prefix_states.pop();
            prefix_states.last().map(|s| s.prefix)
        } else if let Some(cursor) = cursor {
            let remaining = limit - prefix_states.len();
            if remaining > 0 {
                let wrap_query =
                    verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                        .distinct_on("prefix")
                        .order_by("prefix", verifiable_storage_postgres::Order::Asc)
                        .order_by("version", verifiable_storage_postgres::Order::Desc)
                        .lte("prefix", cursor.as_ref())
                        .limit(remaining as u64);
                let wrap_records: Vec<SadPointer> = self.pool.fetch(wrap_query).await?;
                prefix_states.extend(wrap_records.into_iter().map(|r| kels_core::PrefixState {
                    prefix: r.prefix,
                    said: r.said,
                }));
            }
            None
        } else {
            None
        };

        // Batch divergence check
        let page_prefixes: Vec<String> =
            prefix_states.iter().map(|s| s.prefix.to_string()).collect();
        let divergent_query = ColumnQuery::new(Self::TABLE_NAME, "prefix")
            .distinct()
            .r#in("prefix", page_prefixes)
            .group_by("prefix")
            .group_by("version")
            .having_count_gt(1);
        let divergent_prefixes: HashSet<String> = self
            .pool
            .fetch_column(divergent_query)
            .await?
            .into_iter()
            .collect();

        for state in &mut prefix_states {
            if divergent_prefixes.contains(state.prefix.as_ref()) {
                state.said = kels_core::hash_effective_said(&format!("divergent:{}", state.prefix));
            }
        }

        Ok(kels_core::PrefixListResponse {
            prefixes: prefix_states,
            next_cursor,
        })
    }
}

/// Tracks SAD object SAIDs stored in MinIO.
#[derive(Stored)]
#[stored(item_type = kels_core::SadObjectEntry, table = "sad_objects", chained = false)]
pub struct SadObjectIndex {
    pub pool: PgPool,
}

impl SadObjectIndex {
    /// Store a SAD object in MinIO and track it in the index atomically.
    pub async fn store(
        &self,
        sad_said: &cesr::Digest256,
        custody: Option<cesr::Digest256>,
        object_store: &crate::object_store::ObjectStore,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let entry = kels_core::SadObjectEntry::create(*sad_said, custody)?;

        let mut tx = self.pool.begin_transaction().await?;

        match self.insert_in(&mut tx, entry).await {
            Ok(_) => {}
            Err(StorageError::DuplicateRecord(_)) => {
                tx.commit().await?;
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        object_store
            .put(sad_said, data)
            .await
            .map_err(|e| StorageError::StorageError(e.to_string()))?;

        tx.commit().await?;
        Ok(())
    }

    /// Fetch a SAD object index entry by its MinIO SAID.
    pub async fn get_by_sad_said(
        &self,
        sad_said: &cesr::Digest256,
    ) -> Result<Option<kels_core::SadObjectEntry>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
            Self::TABLE_NAME,
        )
        .eq("sad_said", sad_said.as_ref())
        .limit(1);
        self.pool.fetch_optional(query).await
    }

    /// Atomically delete a SAD object index entry by its MinIO SAID.
    /// Returns the number of rows deleted (1 = consumed, 0 = not found/already consumed).
    /// Used for `once` semantics.
    pub async fn delete_by_sad_said(
        &self,
        sad_said: &cesr::Digest256,
    ) -> Result<u64, StorageError> {
        let delete =
            verifiable_storage::Delete::<kels_core::SadObjectEntry>::for_table(Self::TABLE_NAME)
                .eq("sad_said", sad_said.as_ref());
        self.pool.delete(delete).await
    }

    /// Check if a SAD object is tracked.
    pub async fn is_tracked(&self, sad_said: &str) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
            Self::TABLE_NAME,
        )
        .eq("sad_said", sad_said)
        .limit(1);
        Ok(self.pool.fetch_optional(query).await?.is_some())
    }

    /// List SAD object SAIDs, paginated with wrap-around.
    pub async fn list(
        &self,
        cursor: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<kels_core::SadObjectListResponse, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let mut query = verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
            Self::TABLE_NAME,
        )
        .order_by("sad_said", verifiable_storage_postgres::Order::Asc)
        .limit(limit as u64 + 1);

        if let Some(cursor) = cursor {
            query = query.gt("sad_said", cursor.as_ref());
        }

        let entries: Vec<kels_core::SadObjectEntry> = self.pool.fetch(query).await?;

        let mut saids: Vec<cesr::Digest256> = entries.into_iter().map(|e| e.sad_said).collect();

        let next_cursor = if saids.len() > limit {
            saids.pop();
            saids.last().cloned()
        } else if let Some(cursor) = cursor {
            let remaining = limit - saids.len();
            if remaining > 0 {
                let wrap_query =
                    verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
                        Self::TABLE_NAME,
                    )
                    .order_by("sad_said", verifiable_storage_postgres::Order::Asc)
                    .lte("sad_said", cursor.as_ref())
                    .limit(remaining as u64);
                let wrap_entries: Vec<kels_core::SadObjectEntry> =
                    self.pool.fetch(wrap_query).await?;
                saids.extend(wrap_entries.into_iter().map(|e| e.sad_said));
            }
            None
        } else {
            None
        };

        Ok(kels_core::SadObjectListResponse { saids, next_cursor })
    }
}

/// Cached custody SADs for the fetch-time hot path.
#[derive(Stored)]
#[stored(item_type = Custody, table = "custodies", chained = false)]
pub struct CustodyRepository {
    pub pool: PgPool,
}

impl CustodyRepository {
    /// Store a custody SAD in the cache (idempotent).
    pub async fn store(&self, custody: &Custody) -> Result<(), StorageError> {
        match self.insert(custody.clone()).await {
            Ok(_) => Ok(()),
            Err(StorageError::DuplicateRecord(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Fetch a cached custody by SAID.
    pub async fn get_by_said(
        &self,
        said: &cesr::Digest256,
    ) -> Result<Option<Custody>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<Custody>::for_table(Self::TABLE_NAME)
            .eq("said", said.as_ref())
            .limit(1);
        self.pool.fetch_optional(query).await
    }
}

/// Cached policy SADs for evaluation without MinIO round-trips.
#[derive(Stored)]
#[stored(item_type = Policy, table = "policies", chained = false)]
pub struct PolicyRepository {
    pub pool: PgPool,
}

impl PolicyRepository {
    /// Store a policy SAD in the cache (idempotent).
    pub async fn store(&self, policy: &Policy) -> Result<(), StorageError> {
        match self.insert(policy.clone()).await {
            Ok(_) => Ok(()),
            Err(StorageError::DuplicateRecord(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Fetch a cached policy by SAID.
    pub async fn get_by_said(
        &self,
        said: &cesr::Digest256,
    ) -> Result<Option<Policy>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<Policy>::for_table(Self::TABLE_NAME)
            .eq("said", said.as_ref())
            .limit(1);
        self.pool.fetch_optional(query).await
    }
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct SadStoreRepository {
    pub sad_pointers: SadPointerRepository,
    pub sad_objects: SadObjectIndex,
    pub custodies: CustodyRepository,
    pub policies: PolicyRepository,
}
