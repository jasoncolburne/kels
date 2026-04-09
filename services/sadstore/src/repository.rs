//! PostgreSQL Repository for KELS SADStore

use cesr::{Matter, VerificationKey};

use kels_core::{SadPointer, SadPointerRepair, SadPointerRepairRecord, SadPointerSignature};
use verifiable_storage::{
    ChainedRepository, ColumnQuery, QueryExecutor, StorageError, TransactionExecutor,
    UnchainedRepository, Value,
};
use verifiable_storage_postgres::{Filter, PgPool, Stored};

#[derive(Stored)]
#[stored(item_type = SadPointer, table = "sad_pointers", chained = true)]
pub struct SadPointerRepository {
    pub pool: PgPool,
}

impl SadPointerRepository {
    /// The signatures table name.
    pub const SIGNATURES_TABLE_NAME: &'static str = "sad_pointer_signatures";

    /// Store a batch of records with their signatures, with advisory lock and full
    /// chain verification including signature verification against provided keys.
    ///
    /// Acquires an advisory lock on the chain prefix, walks the entire existing chain
    /// to verify structural integrity AND signatures (DB cannot be trusted), then
    /// appends the batch. If a record already exists at the same version with a
    /// different SAID, both are stored and the chain is considered divergent.
    /// Divergent chains are frozen until repaired.
    ///
    /// Returns the number of new records actually inserted (excludes deduplicates).
    pub async fn save_batch_with_verified_signatures(
        &self,
        records: &[(SadPointer, SadPointerSignature)],
        establishment_keys: &std::collections::HashMap<u64, VerificationKey>,
    ) -> Result<u32, StorageError> {
        if records.is_empty() {
            return Ok(0);
        }

        let prefix = records[0].0.prefix;
        let mut tx = self.pool.begin_transaction().await?;
        tx.acquire_advisory_lock(prefix.as_ref()).await?;

        // Quick divergence check before inserting — reject appends to frozen chains
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

        // Insert records, skipping duplicates by checking existence first.
        // We cannot rely on catching unique constraint violations because in
        // Postgres a constraint violation aborts the transaction.
        let existing_saids: std::collections::HashSet<String> = {
            let saids: Vec<String> = records.iter().map(|(r, _)| r.said.to_string()).collect();
            let query =
                verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                    .r#in("said", saids);
            tx.fetch(query)
                .await?
                .into_iter()
                .map(|r: SadPointer| r.said.to_string())
                .collect()
        };

        let mut count = 0u32;
        for (record, signature) in records {
            if existing_saids.contains(&record.said.to_string()) {
                continue;
            }
            self.insert_in(&mut tx, record.clone()).await?;
            tx.insert_with_table(signature, Self::SIGNATURES_TABLE_NAME)
                .await?;
            count += 1;
        }

        // Verify the full chain (including new records) — catches structural
        // issues, signature failures, and DB tampering. Rolls back on failure.
        let verifier = Self::verify_chain(&mut tx, &prefix, establishment_keys).await?;

        // finish() ensures chain is non-empty (DB not wiped)
        verifier.finish().map_err(|e| {
            StorageError::StorageError(format!("Chain verification incomplete: {}", e))
        })?;

        tx.commit().await?;
        Ok(count)
    }

    /// Walk the full chain within a transaction using `SadChainVerifier`.
    /// Verifies structural integrity AND signatures. Returns the verifier
    /// (caller can check `is_divergent()` or call `finish()`).
    async fn verify_chain<Tx: TransactionExecutor>(
        tx: &mut Tx,
        prefix: &cesr::Digest,
        establishment_keys: &std::collections::HashMap<u64, VerificationKey>,
    ) -> Result<kels_core::SadChainVerifier, StorageError> {
        let page_size = kels_core::page_size() as u64;
        let mut verifier = kels_core::SadChainVerifier::new(prefix, establishment_keys.clone());

        let mut offset: u64 = 0;
        loop {
            let query =
                verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                    .eq("prefix", prefix.as_ref())
                    .order_by("version", verifiable_storage_postgres::Order::Asc)
                    .limit(page_size)
                    .offset(offset);
            let page: Vec<SadPointer> = tx.fetch(query).await?;

            if page.is_empty() {
                break;
            }

            // Batch-fetch signatures for this page
            let page_saids: Vec<String> = page.iter().map(|r| r.said.to_string()).collect();
            let sig_query = verifiable_storage_postgres::Query::<SadPointerSignature>::for_table(
                Self::SIGNATURES_TABLE_NAME,
            )
            .r#in("pointer_said", page_saids);
            let sigs: Vec<SadPointerSignature> = tx.fetch(sig_query).await?;
            let sig_map: std::collections::HashMap<cesr::Digest, &SadPointerSignature> =
                sigs.iter().map(|s| (s.pointer_said, s)).collect();

            // Build SignedSadPointers for the verifier
            let signed_records: Vec<kels_core::SignedSadPointer> = page
                .into_iter()
                .map(|record| {
                    let sig_record = sig_map.get(&record.said).ok_or_else(|| {
                        StorageError::StorageError(format!(
                            "Missing signature for record {} — DB tampered",
                            record.said
                        ))
                    })?;
                    Ok(kels_core::SignedSadPointer {
                        pointer: record,
                        signature: sig_record.signature.clone(),
                        establishment_serial: sig_record.establishment_serial,
                    })
                })
                .collect::<Result<Vec<_>, StorageError>>()?;

            verifier.verify_page(&signed_records).map_err(|e| {
                StorageError::StorageError(format!("Chain verification failed: {}", e))
            })?;

            let page_len = signed_records.len() as u64;
            offset += page_len;
            if page_len < page_size {
                break;
            }
        }

        Ok(verifier)
    }

    const ARCHIVED_RECORDS_TABLE: &'static str = "sad_pointer_archives";
    const ARCHIVED_SIGNATURES_TABLE: &'static str = "sad_pointer_archive_signatures";

    /// Truncate records at and after the first replacement's version and insert replacements.
    ///
    /// Used to repair divergent chains. The owner submits a batch starting at the
    /// divergent version. This method archives all records (and their signatures)
    /// at or after that version, creates a `SadChainRepair` audit record, then
    /// inserts the replacements with chain integrity checks. Must be called within
    /// the context of a verified KEL signature.
    pub async fn truncate_and_replace(
        &self,
        records: &[(SadPointer, SadPointerSignature)],
        establishment_keys: &std::collections::HashMap<u64, VerificationKey>,
    ) -> Result<(), StorageError> {
        if records.is_empty() {
            return Err(StorageError::StorageError("Empty batch".to_string()));
        }

        let prefix = records[0].0.prefix;
        let mut tx = self.pool.begin_transaction().await?;
        tx.acquire_advisory_lock(prefix.as_ref()).await?;

        // Verify full chain integrity before modifying — DB cannot be trusted
        Self::verify_chain(&mut tx, &prefix, establishment_keys).await?;

        // Skip leading records that already exist locally (by SAID). The gossip
        // repair path sends the full chain but only the divergent tail needs
        // truncation. Deduplicating here avoids unnecessary archival of records
        // that are identical on both sides.
        let (new_records, from_version) = {
            let saids: Vec<String> = records.iter().map(|r| r.0.said.to_string()).collect();
            let existing_query =
                verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                    .r#in("said", saids);
            let existing: std::collections::HashSet<String> = tx
                .fetch(existing_query)
                .await?
                .into_iter()
                .map(|r: SadPointer| r.said.to_string())
                .collect();
            let deduped: Vec<_> = records
                .iter()
                .skip_while(|(r, _)| existing.contains(&r.said.to_string()))
                .collect();
            if deduped.is_empty() {
                // All replacement records match existing — truncate from the
                // version after the last replacement record (removes the tail).
                let last_version = records.last().map(|(r, _)| r.version).unwrap_or(0);
                (deduped, last_version + 1)
            } else {
                let version = deduped[0].0.version;
                (deduped, version)
            }
        };

        // Archive records and signatures page-at-a-time before deleting
        let page_size = kels_core::page_size();
        let mut repair_said: Option<cesr::Digest> = None;
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

            // Create the repair audit record on first page
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

            let page_saids: Vec<String> = page.iter().map(|r| r.said.to_string()).collect();
            let sig_query = verifiable_storage_postgres::Query::<SadPointerSignature>::for_table(
                Self::SIGNATURES_TABLE_NAME,
            )
            .r#in("pointer_said", page_saids);
            let sigs: Vec<SadPointerSignature> = tx.fetch(sig_query).await?;

            for record in &page {
                tx.insert_with_table(record, Self::ARCHIVED_RECORDS_TABLE)
                    .await?;
                let repair_record = SadPointerRepairRecord::create(*repair_said_ref, record.said)?;
                tx.insert(&repair_record).await?;
            }
            for sig in &sigs {
                tx.insert_with_table(sig, Self::ARCHIVED_SIGNATURES_TABLE)
                    .await?;
            }

            let page_len = page.len();
            if let Some(last) = page.last() {
                version_cursor = last.version + 1;
            }
            if page_len < page_size {
                break;
            }
        }

        // Delete records at and after from_version — signatures cascade via FK ON DELETE CASCADE
        let delete_records = verifiable_storage::Delete::<SadPointer>::for_table(Self::TABLE_NAME)
            .eq("prefix", &prefix)
            .gte("version", from_version);
        tx.delete(delete_records).await?;

        // Insert replacements
        for (record, signature) in new_records {
            self.insert_in(&mut tx, record.clone()).await?;
            tx.insert_with_table(signature, Self::SIGNATURES_TABLE_NAME)
                .await?;
        }

        // Verify the full chain (pre-existing + replacements) — catches structural
        // issues, signature failures, and DB tampering. Rolls back on failure.
        let verifier = Self::verify_chain(&mut tx, &prefix, establishment_keys).await?;
        verifier.finish().map_err(|e| {
            StorageError::StorageError(format!("Chain verification incomplete: {}", e))
        })?;

        tx.commit().await?;
        Ok(())
    }

    /// Quick check: does any version appear more than once for this prefix?
    ///
    /// Uses `GROUP BY version ORDER BY COUNT(*) DESC LIMIT 1` — returns true if
    /// the highest count exceeds 1.
    pub async fn is_divergent(&self, prefix: &str) -> Result<bool, StorageError> {
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
    pub async fn exists(&self, said: &str) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
            .eq("said", said)
            .limit(1);
        Ok(!self.pool.fetch(query).await?.is_empty())
    }

    /// Fetch unique establishment serials from existing signatures for a chain.
    /// Bounded by `max` — returns an error if more than `max` unique serials exist.
    pub async fn existing_establishment_serials(
        &self,
        prefix: &str,
        max: usize,
    ) -> Result<std::collections::BTreeSet<u64>, StorageError> {
        use verifiable_storage::ScalarSubquery;

        let serial_query = ColumnQuery::new(Self::SIGNATURES_TABLE_NAME, "establishment_serial")
            .distinct()
            .in_subquery(
                "pointer_said",
                ScalarSubquery::new(
                    Self::TABLE_NAME,
                    "said",
                    vec![Filter::Eq(
                        "prefix".to_string(),
                        Value::String(prefix.to_string()),
                    )],
                ),
            )
            .limit(max as u64 + 1);
        let serials: Vec<i64> = self.pool.fetch_column(serial_query).await?;

        if serials.len() > max {
            return Err(StorageError::StorageError(format!(
                "Too many unique establishment serials ({} > {})",
                serials.len(),
                max
            )));
        }

        Ok(serials.into_iter().map(|s| s as u64).collect())
    }

    /// Get the chain with signatures as `SignedSadPointer`s.
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
    pub async fn get_stored(
        &self,
        prefix: &str,
        since_said: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Vec<kels_core::SignedSadPointer>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        // Resolve SAID cursor to a (version, said) position
        let since_position: Option<(u64, String)> = if let Some(said) = since_said {
            let cursor_query =
                verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
                    .eq("said", said)
                    .limit(1);
            self.pool
                .fetch(cursor_query)
                .await?
                .into_iter()
                .next()
                .map(|r| (r.version, r.said.to_string()))
        } else {
            None
        };

        let mut query =
            verifiable_storage_postgres::Query::<SadPointer>::for_table(Self::TABLE_NAME)
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
            // Fetch extra to account for records at the cursor version that will
            // be skipped: the cursor record itself (1) plus at most one divergent
            // fork record with a lower SAID (1). The chain is frozen after a single
            // divergence, so +2 is the legitimate maximum.
            let fetch_limit = if since_position.is_some() {
                limit + 2
            } else {
                limit
            };
            query = query.limit(fetch_limit);
        }

        let mut records: Vec<SadPointer> = self.pool.fetch(query).await?;

        // Skip records at or before the cursor position
        if let Some((version, said)) = &since_position {
            let skipped = records.len();
            records.retain(|r| {
                r.version > *version || (r.version == *version && r.said.to_string() > *said)
            });
            let skipped = skipped - records.len();

            // The cursor record itself is always skipped (1). Legitimate divergence
            // adds at most 1 fork record at the cursor version with a lower SAID (2).
            // More than that means the DB was tampered with — fail secure.
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

        if records.is_empty() {
            return Ok(Vec::new());
        }

        // Batch-fetch all signatures in one query
        let saids: Vec<String> = records.iter().map(|r| r.said.to_string()).collect();
        let query =
            verifiable_storage_postgres::Query::<kels_core::SadPointerSignature>::for_table(
                Self::SIGNATURES_TABLE_NAME,
            )
            .r#in("pointer_said", saids);
        let sigs: Vec<kels_core::SadPointerSignature> = self.pool.fetch(query).await?;

        // Index signatures by pointer_said for O(1) lookup
        let sig_map: std::collections::HashMap<cesr::Digest, &kels_core::SadPointerSignature> =
            sigs.iter().map(|s| (s.pointer_said, s)).collect();

        let mut stored = Vec::with_capacity(records.len());
        for record in records {
            let sig = sig_map.get(&record.said).ok_or_else(|| {
                StorageError::StorageError(format!(
                    "Missing signature for SAD record {}",
                    record.said
                ))
            })?;
            stored.push(kels_core::SignedSadPointer {
                pointer: record,
                signature: sig.signature.clone(),
                establishment_serial: sig.establishment_serial,
            });
        }
        Ok(stored)
    }

    /// Get the signature for a SAD record by its SAID.
    pub async fn get_signature(
        &self,
        pointer_said: &str,
    ) -> Result<Option<kels_core::SadPointerSignature>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query =
            verifiable_storage_postgres::Query::<kels_core::SadPointerSignature>::for_table(
                Self::SIGNATURES_TABLE_NAME,
            )
            .eq("pointer_said", pointer_said)
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
        let prefix_digest = cesr::Digest::from_qb64(prefix)
            .map_err(|e| StorageError::StorageError(format!("Invalid prefix CESR: {}", e)))?;
        let latest = self.get_latest(&prefix_digest).await?;
        let Some(latest) = latest else {
            return Ok(None);
        };

        if self.is_divergent(prefix).await? {
            let said = kels_core::hash_effective_said(&format!("divergent:{}", prefix)).to_string();
            return Ok(Some((said, true)));
        }

        Ok(Some((latest.said.to_string(), false)))
    }

    /// Get repairs for a chain prefix, paginated.
    ///
    /// Returns repairs ordered by `repaired_at ASC`. Uses limit+1 overflow
    /// to determine `has_more`.
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
    ///
    /// Fetches `SadPointerRepairRecord` links for the repair SAID, then batch-fetches
    /// the archived records and their signatures. Returns `SignedSadPointer`s.
    pub async fn get_repair_records(
        &self,
        repair_said: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<kels_core::SignedSadPointer>, bool), StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        // Fetch repair-record links with limit+1 for has_more
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

        // Collect record SAIDs
        let pointer_saids: Vec<String> = links.iter().map(|l| l.pointer_said.to_string()).collect();

        // Batch-fetch archived records
        let records_query = verifiable_storage_postgres::Query::<SadPointer>::for_table(
            Self::ARCHIVED_RECORDS_TABLE,
        )
        .r#in("said", pointer_saids.clone());
        let records: Vec<SadPointer> = self.pool.fetch(records_query).await?;

        // Batch-fetch archived signatures
        let sigs_query = verifiable_storage_postgres::Query::<SadPointerSignature>::for_table(
            Self::ARCHIVED_SIGNATURES_TABLE,
        )
        .r#in("pointer_said", pointer_saids);
        let sigs: Vec<SadPointerSignature> = self.pool.fetch(sigs_query).await?;

        // Index signatures by pointer_said
        let sig_map: std::collections::HashMap<cesr::Digest, &SadPointerSignature> =
            sigs.iter().map(|s| (s.pointer_said, s)).collect();

        // Zip into SignedSadPointer
        let mut signed = Vec::with_capacity(records.len());
        for record in records {
            let sig = sig_map.get(&record.said).ok_or_else(|| {
                StorageError::StorageError(format!(
                    "Missing signature for archived record {}",
                    record.said
                ))
            })?;
            signed.push(kels_core::SignedSadPointer {
                pointer: record,
                signature: sig.signature.clone(),
                establishment_serial: sig.establishment_serial,
            });
        }

        Ok((signed, has_more))
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
        cursor: Option<&cesr::Digest>,
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
            // Wrap around: fill remaining slots from prefixes <= cursor
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

        // Batch divergence check: find all prefixes in this page that have
        // duplicate versions, in a single query.
        let page_prefixes: Vec<String> =
            prefix_states.iter().map(|s| s.prefix.to_string()).collect();
        let divergent_query = ColumnQuery::new(Self::TABLE_NAME, "prefix")
            .distinct()
            .r#in("prefix", page_prefixes)
            .group_by("prefix")
            .group_by("version")
            .having_count_gt(1);
        let divergent_prefixes: std::collections::HashSet<String> = self
            .pool
            .fetch_column(divergent_query)
            .await?
            .into_iter()
            .collect();

        // Replace divergent chain SAIDs with synthetic effective SAIDs
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

/// Tracks SAD object SAIDs stored in MinIO (for bootstrap/anti-entropy discovery).
///
/// Uses `SadObjectEntry` as the storable type — a minimal SelfAddressed struct
/// with just a SAID field, matching the `sad_objects` table.
#[derive(Stored)]
#[stored(item_type = kels_core::SadObjectEntry, table = "sad_objects", chained = false)]
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
        let sad_said_digest = cesr::Digest::from_qb64(sad_said)
            .map_err(|e| StorageError::StorageError(format!("Invalid SAID CESR: {}", e)))?;
        let entry = kels_core::SadObjectEntry::create(sad_said_digest)?;

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

        let query = verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
            Self::TABLE_NAME,
        )
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
        cursor: Option<&cesr::Digest>,
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

        let mut saids: Vec<cesr::Digest> = entries.into_iter().map(|e| e.sad_said).collect();

        let next_cursor = if saids.len() > limit {
            saids.pop();
            saids.last().cloned()
        } else if let Some(cursor) = cursor {
            // Wrap around: fill remaining slots from SAIDs <= cursor
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

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct SadStoreRepository {
    pub sad_records: SadPointerRepository,
    pub sad_objects: SadObjectIndex,
}
