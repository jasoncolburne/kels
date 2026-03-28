//! PostgreSQL Repository for KELS SADStore

use kels::{SadRecord, SadRecordSignature};
use verifiable_storage::StorageError;
use verifiable_storage_postgres::{PgPool, Stored};

#[derive(Stored)]
#[stored(item_type = SadRecord, table = "sad_records", chained = true)]
pub struct SadRecordRepository {
    pub pool: PgPool,
}

impl SadRecordRepository {
    /// The signatures table name.
    pub const SIGNATURES_TABLE_NAME: &'static str = "sad_record_signatures";

    /// Store a record with its signature in a transaction.
    ///
    /// Follows the `create_with_signatures` pattern from kels-derive.
    pub async fn insert_with_signature(
        &self,
        record: &SadRecord,
        signature: &SadRecordSignature,
    ) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .inner()
            .begin()
            .await
            .map_err(|e| StorageError::StorageError(e.to_string()))?;

        verifiable_storage_postgres::bind_insert_with_table_tx(&mut tx, record, Self::TABLE_NAME)
            .await?;

        verifiable_storage_postgres::bind_insert_with_table_tx(
            &mut tx,
            signature,
            Self::SIGNATURES_TABLE_NAME,
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| StorageError::StorageError(e.to_string()))?;

        Ok(())
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
