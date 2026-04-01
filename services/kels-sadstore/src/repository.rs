//! PostgreSQL Repository for KELS SADStore

use cesr::{Matter, Signature, VerificationKey};

use kels::{SadChainRepair, SadChainRepairRecord, SadRecord, SadRecordSignature};
use verifiable_storage::{
    Chained, ChainedRepository, ColumnQuery, QueryExecutor, SelfAddressed, StorageError,
    TransactionExecutor, UnchainedRepository, Value,
};
use verifiable_storage_postgres::{Filter, PgPool, Stored};

#[derive(Stored)]
#[stored(item_type = SadRecord, table = "sad_records", chained = true)]
pub struct SadRecordRepository {
    pub pool: PgPool,
}

impl SadRecordRepository {
    /// The signatures table name.
    pub const SIGNATURES_TABLE_NAME: &'static str = "sad_record_signatures";

    /// Store a batch of records with their signatures, with advisory lock and full
    /// chain verification including signature verification against provided keys.
    ///
    /// Acquires an advisory lock on the chain prefix, walks the entire existing chain
    /// to verify structural integrity AND signatures (DB cannot be trusted), then
    /// appends the batch with signature verification. If a record already exists at
    /// the same version with a different SAID, both are stored and the chain is
    /// considered divergent. Divergent chains are frozen until repaired.
    ///
    /// `establishment_keys` maps KEL serial → public key (CESR qb64). Must contain
    /// keys for all serials used by both existing and new records.
    ///
    /// Returns the number of new records actually inserted (excludes deduplicates).
    pub async fn save_batch_with_verified_signatures(
        &self,
        records: &[(SadRecord, SadRecordSignature)],
        establishment_keys: &std::collections::HashMap<u64, VerificationKey>,
    ) -> Result<u32, StorageError> {
        if records.is_empty() {
            return Ok(0);
        }

        let prefix = &records[0].0.prefix;
        let mut tx = self.pool.begin_transaction().await?;
        tx.acquire_advisory_lock(prefix).await?;

        // Walk the full chain to verify integrity — DB cannot be trusted.
        let page_size = kels::page_size() as u64;
        let mut expected_version: u64 = 0;
        let mut last_said: Option<String> = None;
        let mut chain_kel_prefix: Option<String> = None;
        let mut chain_kind: Option<String> = None;
        let mut is_divergent = false;
        let mut tip_said: Option<String> = None;

        let mut offset: u64 = 0;
        loop {
            let query =
                verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                    .eq("prefix", prefix)
                    .order_by("version", verifiable_storage_postgres::Order::Asc)
                    .limit(page_size)
                    .offset(offset);
            let page: Vec<SadRecord> = tx.fetch(query).await?;

            if page.is_empty() {
                break;
            }

            // Batch-fetch signatures for this page
            let page_saids: Vec<String> = page.iter().map(|r| r.said.clone()).collect();
            let sig_query = verifiable_storage_postgres::Query::<SadRecordSignature>::for_table(
                Self::SIGNATURES_TABLE_NAME,
            )
            .r#in("record_said", page_saids);
            let sigs: Vec<SadRecordSignature> = tx.fetch(sig_query).await?;
            let sig_map: std::collections::HashMap<&str, &SadRecordSignature> =
                sigs.iter().map(|s| (s.record_said.as_str(), s)).collect();

            for existing in &page {
                // Divergence: duplicate version (same version as previous record)
                if existing.version + 1 == expected_version {
                    is_divergent = true;
                    continue;
                }

                if existing.version == 0 {
                    // v0: verify prefix derivation
                    if existing.verify_prefix().is_err() {
                        return Err(StorageError::StorageError(
                            "Existing v0 record has invalid prefix derivation — DB tampered"
                                .to_string(),
                        ));
                    }
                    chain_kel_prefix = Some(existing.kel_prefix.clone());
                    chain_kind = Some(existing.kind.clone());
                } else {
                    // Verify chain linkage
                    if existing.previous.as_deref() != last_said.as_deref() {
                        return Err(StorageError::StorageError(
                            "Existing chain has broken linkage — DB tampered".to_string(),
                        ));
                    }
                    if existing.version != expected_version {
                        return Err(StorageError::StorageError(
                            "Existing chain has non-sequential versions — DB tampered".to_string(),
                        ));
                    }
                    if chain_kel_prefix.as_deref() != Some(&existing.kel_prefix) {
                        return Err(StorageError::StorageError(
                            "Existing chain has inconsistent kel_prefix — DB tampered".to_string(),
                        ));
                    }
                    if chain_kind.as_deref() != Some(&existing.kind) {
                        return Err(StorageError::StorageError(
                            "Existing chain has inconsistent kind — DB tampered".to_string(),
                        ));
                    }
                }

                // Verify SAID integrity
                if existing.verify_said().is_err() {
                    return Err(StorageError::StorageError(
                        "Existing record has invalid SAID — DB tampered".to_string(),
                    ));
                }

                // Verify signature against establishment key
                let sig_record = sig_map.get(existing.said.as_str()).ok_or_else(|| {
                    StorageError::StorageError(format!(
                        "Missing signature for existing record {} — DB tampered",
                        existing.said
                    ))
                })?;
                let public_key = establishment_keys
                    .get(&sig_record.establishment_serial)
                    .ok_or_else(|| {
                        StorageError::StorageError(format!(
                            "No establishment key for serial {} — DB tampered",
                            sig_record.establishment_serial
                        ))
                    })?;
                let sig = Signature::from_qb64(&sig_record.signature).map_err(|e| {
                    StorageError::StorageError(format!("Invalid signature format: {}", e))
                })?;
                if public_key.verify(existing.said.as_bytes(), &sig).is_err() {
                    return Err(StorageError::StorageError(format!(
                        "Signature verification failed for existing record {} — DB tampered",
                        existing.said
                    )));
                }

                last_said = Some(existing.said.clone());
                tip_said = Some(existing.said.clone());
                expected_version = existing.version + 1;
            }

            let page_len = page.len() as u64;
            offset += page_len;
            if page_len < page_size {
                break;
            }
        }

        // Reject appends to divergent chains
        if is_divergent {
            tx.commit().await?;
            return Err(StorageError::StorageError(
                "Chain is divergent — repair required".to_string(),
            ));
        }

        // Append new records
        let mut count = 0u32;
        for (record, signature) in records {
            // Check for existing record at this version (dedup or divergence)
            let existing_at_version: Option<SadRecord> = {
                let query =
                    verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                        .eq("prefix", prefix)
                        .eq("version", record.version)
                        .limit(1);
                tx.fetch(query).await?.into_iter().next()
            };

            if let Some(existing) = existing_at_version {
                if existing.said == record.said {
                    // Deduplicated — skip
                    continue;
                }

                // v0 divergence is impossible (deterministic)
                if record.version == 0 {
                    return Err(StorageError::StorageError(
                        "v0 inception record conflict — content must be deterministic".to_string(),
                    ));
                }

                // Divergence: store both, chain is now frozen
                self.insert_in(&mut tx, record.clone()).await?;
                tx.insert_with_table(signature, Self::SIGNATURES_TABLE_NAME)
                    .await?;
                count += 1;
                tx.commit().await?;
                return Ok(count);
            }

            // Validate chaining against the current tip
            if record.version == 0 {
                if tip_said.is_some() {
                    return Err(StorageError::StorageError(
                        "Chain already exists".to_string(),
                    ));
                }
                if record.verify_prefix().is_err() {
                    return Err(StorageError::StorageError(
                        "v0 prefix derivation verification failed".to_string(),
                    ));
                }
            } else {
                if record.previous.as_deref() != tip_said.as_deref() {
                    return Err(StorageError::StorageError(
                        "Previous SAID does not match chain tip".to_string(),
                    ));
                }
                if let Some(ref kp) = chain_kel_prefix
                    && record.kel_prefix != *kp
                {
                    return Err(StorageError::StorageError(
                        "kel_prefix mismatch".to_string(),
                    ));
                }
                if let Some(ref k) = chain_kind
                    && record.kind != *k
                {
                    return Err(StorageError::StorageError("kind mismatch".to_string()));
                }
                if record.version != expected_version {
                    return Err(StorageError::StorageError(
                        "Version is not sequential".to_string(),
                    ));
                }
            }

            self.insert_in(&mut tx, record.clone()).await?;
            tx.insert_with_table(signature, Self::SIGNATURES_TABLE_NAME)
                .await?;
            count += 1;

            // Update tracking for next record in batch
            tip_said = Some(record.said.clone());
            expected_version = record.version + 1;
            if chain_kel_prefix.is_none() {
                chain_kel_prefix = Some(record.kel_prefix.clone());
            }
            if chain_kind.is_none() {
                chain_kind = Some(record.kind.clone());
            }
        }

        tx.commit().await?;
        Ok(count)
    }

    const ARCHIVED_RECORDS_TABLE: &'static str = "sad_record_archives";
    const ARCHIVED_SIGNATURES_TABLE: &'static str = "sad_record_archive_signatures";
    const REPAIRS_TABLE: &'static str = "sad_chain_repairs";
    const REPAIR_RECORDS_TABLE: &'static str = "sad_chain_repair_records";

    /// Truncate records at version >= `from_version` and insert replacements.
    ///
    /// Used to repair divergent chains. The owner submits a batch starting at the
    /// divergent version. This method archives all records (and their signatures)
    /// at or after that version, creates a `SadChainRepair` audit record, then
    /// inserts the replacements with chain integrity checks. Must be called within
    /// the context of a verified KEL signature.
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

        // Archive records and signatures page-at-a-time before deleting
        let page_size = kels::page_size();
        let mut repair_said: Option<String> = None;
        let mut version_cursor = from_version;

        loop {
            let page_query =
                verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                    .eq("prefix", prefix)
                    .gte("version", version_cursor)
                    .order_by("version", verifiable_storage::Order::Asc)
                    .limit(page_size as u64);
            let page: Vec<SadRecord> = tx.fetch(page_query).await?;

            if page.is_empty() {
                break;
            }

            // Create the repair audit record on first page
            let repair_said_ref = match &repair_said {
                Some(said) => said,
                None => {
                    let repair = SadChainRepair::create(prefix.clone(), from_version)?;
                    tx.insert_with_table(&repair, Self::REPAIRS_TABLE).await?;
                    repair_said = Some(repair.said);
                    repair_said.as_ref().ok_or_else(|| {
                        StorageError::StorageError("repair SAID missing".to_string())
                    })?
                }
            };

            let page_saids: Vec<String> = page.iter().map(|r| r.said.clone()).collect();
            let sig_query = verifiable_storage_postgres::Query::<SadRecordSignature>::for_table(
                Self::SIGNATURES_TABLE_NAME,
            )
            .r#in("record_said", page_saids);
            let sigs: Vec<SadRecordSignature> = tx.fetch(sig_query).await?;

            for record in &page {
                tx.insert_with_table(record, Self::ARCHIVED_RECORDS_TABLE)
                    .await?;
                let repair_record =
                    SadChainRepairRecord::create(repair_said_ref.clone(), record.said.clone())?;
                tx.insert_with_table(&repair_record, Self::REPAIR_RECORDS_TABLE)
                    .await?;
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

        // Verify internal chain linkage of replacement batch
        for window in records.windows(2) {
            let (prev, next) = (&window[0].0, &window[1].0);
            if next.previous.as_deref() != Some(&prev.said) {
                return Err(StorageError::StorageError(
                    "Replacement batch has broken chain linkage".to_string(),
                ));
            }
            if next.version != prev.version + 1 {
                return Err(StorageError::StorageError(
                    "Replacement batch has non-sequential versions".to_string(),
                ));
            }
            if next.kel_prefix != prev.kel_prefix {
                return Err(StorageError::StorageError(
                    "Replacement batch has inconsistent kel_prefix".to_string(),
                ));
            }
            if next.kind != prev.kind {
                return Err(StorageError::StorageError(
                    "Replacement batch has inconsistent kind".to_string(),
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

    /// Fetch all unique establishment serials from existing signatures for a chain.
    pub async fn existing_establishment_serials(
        &self,
        prefix: &str,
    ) -> Result<std::collections::BTreeSet<u64>, StorageError> {
        // Get all record SAIDs for this chain
        let record_query =
            verifiable_storage_postgres::Query::<SadRecord>::for_table(Self::TABLE_NAME)
                .eq("prefix", prefix);
        let records: Vec<SadRecord> = self.pool.fetch(record_query).await?;
        if records.is_empty() {
            return Ok(std::collections::BTreeSet::new());
        }

        let record_saids: Vec<String> = records.iter().map(|r| r.said.clone()).collect();
        let sig_query = verifiable_storage_postgres::Query::<SadRecordSignature>::for_table(
            Self::SIGNATURES_TABLE_NAME,
        )
        .r#in("record_said", record_saids);
        let sigs: Vec<SadRecordSignature> = self.pool.fetch(sig_query).await?;
        Ok(sigs.iter().map(|s| s.establishment_serial).collect())
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

        let mut records: Vec<SadRecord> = self.pool.fetch(query).await?;

        // Skip records at or before the cursor position
        if let Some((version, said)) = &since_position {
            let skipped = records.len();
            records.retain(|r| r.version > *version || (r.version == *version && r.said > *said));
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

    /// Get repairs for a chain prefix, paginated.
    ///
    /// Returns repairs ordered by `repaired_at ASC`. Uses limit+1 overflow
    /// to determine `has_more`.
    pub async fn get_repairs(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<kels::SadChainRepair>, bool), StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<kels::SadChainRepair>::for_table(
            Self::REPAIRS_TABLE,
        )
        .eq("record_prefix", prefix)
        .order_by("repaired_at", verifiable_storage_postgres::Order::Asc)
        .offset(offset)
        .limit(limit + 1);
        let mut repairs: Vec<kels::SadChainRepair> = self.pool.fetch(query).await?;

        let has_more = repairs.len() as u64 > limit;
        repairs.truncate(limit as usize);
        Ok((repairs, has_more))
    }

    /// Get archived records for a specific repair, paginated.
    ///
    /// Fetches `SadChainRepairRecord` links for the repair SAID, then batch-fetches
    /// the archived records and their signatures. Returns `SignedSadRecord`s.
    pub async fn get_repair_records(
        &self,
        repair_said: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<kels::SignedSadRecord>, bool), StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        // Fetch repair-record links with limit+1 for has_more
        let link_query = verifiable_storage_postgres::Query::<SadChainRepairRecord>::for_table(
            Self::REPAIR_RECORDS_TABLE,
        )
        .eq("repair_said", repair_said)
        .offset(offset)
        .limit(limit + 1);
        let mut links: Vec<SadChainRepairRecord> = self.pool.fetch(link_query).await?;

        let has_more = links.len() as u64 > limit;
        links.truncate(limit as usize);

        if links.is_empty() {
            return Ok((Vec::new(), false));
        }

        // Collect record SAIDs
        let record_saids: Vec<String> = links.iter().map(|l| l.record_said.clone()).collect();

        // Batch-fetch archived records
        let records_query = verifiable_storage_postgres::Query::<SadRecord>::for_table(
            Self::ARCHIVED_RECORDS_TABLE,
        )
        .r#in("said", record_saids.clone());
        let records: Vec<SadRecord> = self.pool.fetch(records_query).await?;

        // Batch-fetch archived signatures
        let sigs_query = verifiable_storage_postgres::Query::<SadRecordSignature>::for_table(
            Self::ARCHIVED_SIGNATURES_TABLE,
        )
        .r#in("record_said", record_saids);
        let sigs: Vec<SadRecordSignature> = self.pool.fetch(sigs_query).await?;

        // Index signatures by record_said
        let sig_map: std::collections::HashMap<&str, &SadRecordSignature> =
            sigs.iter().map(|s| (s.record_said.as_str(), s)).collect();

        // Zip into SignedSadRecord
        let mut signed = Vec::with_capacity(records.len());
        for record in records {
            let sig = sig_map.get(record.said.as_str()).ok_or_else(|| {
                StorageError::StorageError(format!(
                    "Missing signature for archived record {}",
                    record.said
                ))
            })?;
            signed.push(kels::SignedSadRecord {
                record,
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

        // Batch divergence check: find all prefixes in this page that have
        // duplicate versions, in a single query.
        let page_prefixes: Vec<String> = prefix_states.iter().map(|s| s.prefix.clone()).collect();
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
            if divergent_prefixes.contains(&state.prefix) {
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
