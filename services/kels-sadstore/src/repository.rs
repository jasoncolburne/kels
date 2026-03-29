//! PostgreSQL Repository for KELS SADStore

use kels::{SadRecord, SadRecordSignature};
use verifiable_storage::{
    ChainedRepository, QueryExecutor as _, StorageError, TransactionExecutor, UnchainedRepository,
};
use verifiable_storage_postgres::{PgPool, Stored};

#[derive(Stored)]
#[stored(item_type = SadRecord, table = "sad_records", chained = true)]
pub struct SadRecordRepository {
    pub pool: PgPool,
}

impl SadRecordRepository {
    /// The signatures table name.
    pub const SIGNATURES_TABLE_NAME: &'static str = "sad_record_signatures";

    /// Store a record with its signature, with advisory lock and chain integrity checks.
    ///
    /// **Precondition:** the caller must have already verified the record's signature
    /// against the KEL. This method does not verify signatures — it trusts the caller.
    ///
    /// Acquires an advisory lock on the chain prefix, validates the chain, and detects
    /// divergence. If a record already exists at the same version with a different SAID,
    /// both records are stored and the chain is considered divergent. Divergent chains
    /// are frozen — no further appends are accepted until repaired via `truncate_and_replace`.
    ///
    /// v0 divergence is rejected as an error (inception records are fully deterministic).
    pub async fn save_with_verified_signature(
        &self,
        record: &SadRecord,
        signature: &SadRecordSignature,
    ) -> Result<bool, StorageError> {
        let mut tx = self.pool.begin_transaction().await?;

        tx.acquire_advisory_lock(&record.prefix).await?;

        // Check if chain is already divergent — reject appends if so
        if self.is_divergent_in(&mut tx, &record.prefix).await? {
            tx.commit().await?;
            return Err(StorageError::StorageError(
                "Chain is divergent — repair required".to_string(),
            ));
        }

        // Check for existing record at this version
        let existing_at_version: Option<SadRecord> = {
            let query =
                verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                    .eq("prefix", &record.prefix)
                    .eq("version", record.version)
                    .limit(1);
            tx.fetch(query).await?.into_iter().next()
        };

        if let Some(existing) = existing_at_version {
            if existing.said == record.said {
                // Identical record already stored — deduplicated
                tx.commit().await?;
                return Ok(false);
            }

            // v0 divergence is impossible (deterministic content) — reject
            if record.version == 0 {
                return Err(StorageError::StorageError(
                    "v0 inception record conflict — content must be deterministic".to_string(),
                ));
            }

            // Divergence detected: store both records. Chain is now frozen.
            self.insert_in(&mut tx, record.clone()).await?;
            tx.insert_with_table(signature, Self::SIGNATURES_TABLE_NAME)
                .await?;
            tx.commit().await?;
            return Ok(true);
        }

        // No existing record at this version — validate chain integrity
        let tip: Option<SadRecord> = {
            let query =
                verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                    .eq("prefix", &record.prefix)
                    .order_by("version", verifiable_storage_postgres::Order::Desc)
                    .limit(1);
            tx.fetch(query).await?.into_iter().next()
        };

        if record.version == 0 {
            if tip.is_some() {
                return Err(StorageError::StorageError(
                    "Chain already exists".to_string(),
                ));
            }
        } else {
            let Some(tip) = tip else {
                return Err(StorageError::StorageError("Chain not found".to_string()));
            };

            if record.previous.as_deref() != Some(&tip.said) {
                return Err(StorageError::StorageError(
                    "Previous SAID does not match chain tip".to_string(),
                ));
            }

            if record.kel_prefix != tip.kel_prefix {
                return Err(StorageError::StorageError(
                    "kel_prefix mismatch".to_string(),
                ));
            }

            if record.kind != tip.kind {
                return Err(StorageError::StorageError("kind mismatch".to_string()));
            }

            if record.version != tip.version + 1 {
                return Err(StorageError::StorageError(
                    "Version is not sequential".to_string(),
                ));
            }
        }

        self.insert_in(&mut tx, record.clone()).await?;
        tx.insert_with_table(signature, Self::SIGNATURES_TABLE_NAME)
            .await?;

        tx.commit().await?;

        Ok(true)
    }

    /// Truncate records at version >= `from_version` and insert replacements.
    ///
    /// Used to repair divergent chains. The owner submits a batch starting at the
    /// divergent version. This method deletes all records (and their signatures)
    /// at or after that version, then inserts the replacements with chain integrity
    /// checks. Must be called within the context of a verified KEL signature.
    pub async fn truncate_and_replace(
        &self,
        from_version: u64,
        records: &[(SadRecord, SadRecordSignature)],
    ) -> Result<(), StorageError> {
        if records.is_empty() {
            return Err(StorageError::StorageError("Empty batch".to_string()));
        }

        let prefix = &records[0].0.prefix;
        let mut tx = self.pool.begin_transaction().await?;
        tx.acquire_advisory_lock(prefix).await?;

        // Delete records at and after from_version — signatures cascade via FK ON DELETE CASCADE
        let delete_records = verifiable_storage::Delete::<SadRecord>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .gte("version", from_version);
        tx.delete(delete_records).await?;

        // Validate chain integrity from the predecessor
        if from_version > 0 {
            let predecessor: Option<SadRecord> = {
                let query =
                    verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                        .eq("prefix", prefix)
                        .eq("version", from_version - 1)
                        .limit(1);
                tx.fetch(query).await?.into_iter().next()
            };

            let Some(pred) = predecessor else {
                return Err(StorageError::StorageError(
                    "Predecessor record not found".to_string(),
                ));
            };

            let first = &records[0].0;
            if first.previous.as_deref() != Some(&pred.said) {
                return Err(StorageError::StorageError(
                    "First replacement record doesn't chain from predecessor".to_string(),
                ));
            }
        }

        // Insert replacements
        for (record, signature) in records {
            self.insert_in(&mut tx, record.clone()).await?;
            tx.insert_with_table(signature, Self::SIGNATURES_TABLE_NAME)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Check whether a chain is divergent (multiple records at the same version).
    pub async fn is_divergent(&self, prefix: &str) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let records: Vec<SadRecord> = {
            let query =
                verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                    .eq("prefix", prefix)
                    .order_by("version", verifiable_storage_postgres::Order::Asc)
                    .order_by("said", verifiable_storage_postgres::Order::Asc);
            self.pool.fetch(query).await?
        };

        for window in records.windows(2) {
            if window[0].version == window[1].version {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check divergence within a transaction.
    async fn is_divergent_in<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        prefix: &str,
    ) -> Result<bool, StorageError> {
        let records: Vec<SadRecord> = {
            let query =
                verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                    .eq("prefix", prefix)
                    .order_by("version", verifiable_storage_postgres::Order::Asc)
                    .order_by("said", verifiable_storage_postgres::Order::Asc);
            tx.fetch(query).await?
        };

        for window in records.windows(2) {
            if window[0].version == window[1].version {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Get the chain with signatures as `SignedSadRecord`s.
    ///
    /// If `since_said` is provided, looks up that SAID's record and returns
    /// records strictly after it in chain order. If the SAID is not found
    /// (e.g. synthetic divergent SAID), returns the full chain.
    ///
    /// If `limit` is provided, returns at most that many records.
    /// Fetches records and signatures in two queries (not N+1).
    ///
    /// Ordering: `version ASC, said ASC` — deterministic across nodes even when
    /// divergent records exist at the same version.
    pub async fn get_stored_chain(
        &self,
        prefix: &str,
        since_said: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Vec<kels::SignedSadRecord>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        // Resolve SAID cursor to a (version, said) position
        let since_position: Option<(u64, String)> = if let Some(said) = since_said {
            let cursor_query =
                verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                    .eq("said", said)
                    .limit(1);
            self.pool
                .fetch(cursor_query)
                .await?
                .into_iter()
                .next()
                .map(|r| (r.version, r.said))
        } else {
            None
        };

        let mut query =
            verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                .eq("prefix", prefix)
                .order_by("version", verifiable_storage_postgres::Order::Asc)
                .order_by("said", verifiable_storage_postgres::Order::Asc);

        if let Some((version, _)) = &since_position {
            // Records strictly after this position: same version with greater SAID,
            // or any later version.
            // Since the query builder doesn't support OR, fetch from this version
            // and skip records <= the cursor position in-memory.
            query = query.gte("version", *version);
        }

        if let Some(limit) = limit {
            // Fetch extra to account for records we'll skip at the cursor position
            let fetch_limit = if since_position.is_some() {
                limit + kels::page_size() as u64
            } else {
                limit
            };
            query = query.limit(fetch_limit);
        }

        let mut records: Vec<SadRecord> = self.pool.fetch(query).await?;

        // Skip records at or before the cursor position
        if let Some((version, said)) = &since_position {
            records.retain(|r| r.version > *version || (r.version == *version && r.said > *said));
            if let Some(limit) = limit {
                records.truncate(limit as usize);
            }
        }

        if records.is_empty() {
            return Ok(Vec::new());
        }

        // Batch-fetch all signatures in one query
        let saids: Vec<String> = records.iter().map(|r| r.said.clone()).collect();
        let query = verifiable_storage_postgres::Query::<kels::SadRecordSignature>::for_table(
            Self::SIGNATURES_TABLE_NAME,
        )
        .r#in("record_said", saids);
        let sigs: Vec<kels::SadRecordSignature> = self.pool.fetch(query).await?;

        // Index signatures by record_said for O(1) lookup
        let sig_map: std::collections::HashMap<&str, &kels::SadRecordSignature> =
            sigs.iter().map(|s| (s.record_said.as_str(), s)).collect();

        let mut stored = Vec::with_capacity(records.len());
        for record in records {
            let sig = sig_map.get(record.said.as_str()).ok_or_else(|| {
                StorageError::StorageError(format!(
                    "Missing signature for SAD record {}",
                    record.said
                ))
            })?;
            stored.push(kels::SignedSadRecord {
                record,
                signature: sig.signature.clone(),
                establishment_serial: sig.establishment_serial,
            });
        }
        Ok(stored)
    }

    /// Get the signature for a SAD record by its SAID.
    pub async fn get_signature(
        &self,
        record_said: &str,
    ) -> Result<Option<kels::SadRecordSignature>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<kels::SadRecordSignature>::for_table(
            Self::SIGNATURES_TABLE_NAME,
        )
        .eq("record_said", record_said)
        .limit(1);
        self.pool.fetch_optional(query).await
    }

    /// Get the effective SAID for a chain prefix.
    ///
    /// Returns `(said, divergent)`. For divergent chains, returns a synthetic
    /// deterministic SAID so all nodes agree on the divergent state.
    pub async fn effective_said(
        &self,
        prefix: &str,
    ) -> Result<Option<(String, bool)>, StorageError> {
        let latest = self.get_latest(prefix).await?;
        let Some(latest) = latest else {
            return Ok(None);
        };

        if self.is_divergent(prefix).await? {
            let said = kels::hash_effective_said(&format!("divergent:{}", prefix));
            return Ok(Some((said, true)));
        }

        Ok(Some((latest.said, false)))
    }

    /// List chain prefixes with their effective SAIDs, paginated by cursor.
    ///
    /// Wraps around: if `cursor` is provided and the query returns fewer than
    /// `limit` results, fills remaining slots from the beginning of the prefix
    /// space (prefixes <= cursor). This ensures unbiased random sampling.
    ///
    /// Divergent chains get a synthetic effective SAID.
    pub async fn list_prefixes(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<kels::PrefixListResponse, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let mut query =
            verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                .distinct_on("prefix")
                .order_by("prefix", verifiable_storage_postgres::Order::Asc)
                .order_by("version", verifiable_storage_postgres::Order::Desc)
                .limit(limit as u64 + 1);

        if let Some(cursor) = cursor {
            query = query.gt("prefix", cursor);
        }

        let records: Vec<SadRecord> = self.pool.fetch(query).await?;

        let mut prefix_states: Vec<kels::PrefixState> = records
            .into_iter()
            .map(|r| kels::PrefixState {
                prefix: r.prefix,
                said: r.said,
            })
            .collect();

        let next_cursor = if prefix_states.len() > limit {
            prefix_states.pop();
            prefix_states.last().map(|s| s.prefix.clone())
        } else if let Some(cursor) = cursor {
            // Wrap around: fill remaining slots from prefixes <= cursor
            let remaining = limit - prefix_states.len();
            if remaining > 0 {
                let wrap_query =
                    verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                        .distinct_on("prefix")
                        .order_by("prefix", verifiable_storage_postgres::Order::Asc)
                        .order_by("version", verifiable_storage_postgres::Order::Desc)
                        .lte("prefix", cursor)
                        .limit(remaining as u64);
                let wrap_records: Vec<SadRecord> = self.pool.fetch(wrap_query).await?;
                prefix_states.extend(wrap_records.into_iter().map(|r| kels::PrefixState {
                    prefix: r.prefix,
                    said: r.said,
                }));
            }
            None
        } else {
            None
        };

        // Replace divergent chain SAIDs with synthetic effective SAIDs
        for state in &mut prefix_states {
            if self.is_divergent(&state.prefix).await? {
                state.said = kels::hash_effective_said(&format!("divergent:{}", state.prefix));
            }
        }

        Ok(kels::PrefixListResponse {
            prefixes: prefix_states,
            next_cursor,
        })
    }
}

/// Tracks SAD object SAIDs stored in MinIO (for bootstrap/anti-entropy discovery).
///
/// Uses `SadObjectEntry` as the storable type — a minimal SelfAddressed struct
/// with just a SAID field, matching the `sad_objects` table.
#[derive(Stored)]
#[stored(item_type = kels::SadObjectEntry, table = "sad_objects", chained = false)]
pub struct SadObjectIndex {
    pub pool: PgPool,
}

impl SadObjectIndex {
    /// Store a SAD object in MinIO and track it in the index atomically.
    ///
    /// Opens a DB transaction, inserts the index entry, writes to MinIO,
    /// then commits. If MinIO fails, the transaction rolls back on drop.
    pub async fn store(
        &self,
        sad_said: &str,
        object_store: &crate::object_store::ObjectStore,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let entry = kels::SadObjectEntry::create(sad_said.to_string())?;

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

    /// Check if a SAD object is tracked.
    pub async fn is_tracked(&self, sad_said: &str) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query =
            verifiable_storage_postgres::Query::<kels::SadObjectEntry>::for_table(Self::TABLE_NAME)
                .eq("sad_said", sad_said)
                .limit(1);
        Ok(self.pool.fetch_optional(query).await?.is_some())
    }

    /// List SAD object SAIDs (the MinIO keys), paginated by cursor with wrap-around.
    ///
    /// Wraps around: if `cursor` is provided and the query returns fewer than
    /// `limit` results, fills remaining slots from the beginning of the SAID
    /// space (SAIDs <= cursor). Ensures unbiased random sampling for anti-entropy.
    pub async fn list(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<kels::SadObjectListResponse, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let mut query =
            verifiable_storage_postgres::Query::<kels::SadObjectEntry>::for_table(Self::TABLE_NAME)
                .order_by("sad_said", verifiable_storage_postgres::Order::Asc)
                .limit(limit as u64 + 1);

        if let Some(cursor) = cursor {
            query = query.gt("sad_said", cursor);
        }

        let entries: Vec<kels::SadObjectEntry> = self.pool.fetch(query).await?;

        let mut saids: Vec<String> = entries.into_iter().map(|e| e.sad_said).collect();

        let next_cursor = if saids.len() > limit {
            saids.pop();
            saids.last().cloned()
        } else if let Some(cursor) = cursor {
            // Wrap around: fill remaining slots from SAIDs <= cursor
            let remaining = limit - saids.len();
            if remaining > 0 {
                let wrap_query =
                    verifiable_storage_postgres::Query::<kels::SadObjectEntry>::for_table(
                        Self::TABLE_NAME,
                    )
                    .order_by("sad_said", verifiable_storage_postgres::Order::Asc)
                    .lte("sad_said", cursor)
                    .limit(remaining as u64);
                let wrap_entries: Vec<kels::SadObjectEntry> = self.pool.fetch(wrap_query).await?;
                saids.extend(wrap_entries.into_iter().map(|e| e.sad_said));
            }
            None
        } else {
            None
        };

        Ok(kels::SadObjectListResponse { saids, next_cursor })
    }
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct SadStoreRepository {
    pub sad_records: SadRecordRepository,
    pub sad_objects: SadObjectIndex,
}
