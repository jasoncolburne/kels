//! PostgreSQL Repository for KELS SADStore

use kels::{SadRecord, SadRecordSignature};
use verifiable_storage::{QueryExecutor as _, StorageError, TransactionExecutor};
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
    /// Acquires an advisory lock on the chain prefix, validates the chain, and handles
    /// conflicts deterministically: if a record already exists at the same version,
    /// the record with the lexicographically smaller SAID wins. This ensures all nodes
    /// converge on the same record regardless of write order (prevents split-brain from
    /// concurrent writes to different nodes).
    ///
    /// Returns `Ok(())` on success, or an error describing the chain integrity violation.
    pub async fn save_with_chain_check(
        &self,
        record: &SadRecord,
        signature: &SadRecordSignature,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin_transaction().await?;

        tx.acquire_advisory_lock(&record.prefix).await?;

        // Check for existing record at this version (conflict detection)
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
                // Identical record already stored — idempotent success
                tx.commit().await?;
                return Ok(());
            }

            // Conflict: two different records at the same version.
            // Deterministic resolution: smallest SAID wins.
            if record.said >= existing.said {
                // Incoming record loses — reject silently
                tx.commit().await?;
                return Ok(());
            }

            // Incoming record wins — replace existing record + signature
            let delete_record =
                verifiable_storage::Delete::<SadRecord>::for_table(Self::TABLE_NAME)
                    .eq("said", &existing.said);
            tx.delete(delete_record).await?;
            let delete_sig = verifiable_storage::Delete::<SadRecordSignature>::for_table(
                Self::SIGNATURES_TABLE_NAME,
            )
            .eq("record_said", &existing.said);
            tx.delete(delete_sig).await?;
        } else {
            // No conflict — validate chain integrity
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
        }

        tx.insert_with_table(record, Self::TABLE_NAME).await?;
        tx.insert_with_table(signature, Self::SIGNATURES_TABLE_NAME)
            .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Get the full chain with signatures as `SignedSadRecord`s.
    pub async fn get_stored_chain(
        &self,
        prefix: &str,
    ) -> Result<Vec<kels::SignedSadRecord>, StorageError> {
        use verifiable_storage::ChainedRepository;

        let records = self.get_history(prefix).await?;
        let mut stored = Vec::with_capacity(records.len());
        for record in records {
            let sig = self.get_signature(&record.said).await?;
            let Some(sig) = sig else {
                return Err(StorageError::StorageError(format!(
                    "Missing signature for SAD record {}",
                    record.said
                )));
            };
            stored.push(kels::SignedSadRecord {
                record,
                signature: sig.signature,
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

    /// Get the effective SAID (tip record's SAID) for a chain prefix.
    pub async fn effective_said(&self, prefix: &str) -> Result<Option<String>, StorageError> {
        use verifiable_storage::ChainedRepository;
        Ok(self.get_latest(prefix).await?.map(|r| r.said))
    }
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct SadStoreRepository {
    pub sad_records: SadRecordRepository,
}
