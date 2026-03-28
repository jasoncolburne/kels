//! PostgreSQL Repository for KELS SADStore

use verifiable_storage_postgres::{PgPool, Stored};

use kels::SadRecord;

#[derive(Stored)]
#[stored(item_type = SadRecord, table = "sad_records", chained = true)]
pub struct SadRecordRepository {
    pub pool: PgPool,
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct SadStoreRepository {
    pub sad_records: SadRecordRepository,
}
