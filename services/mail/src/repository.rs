//! PostgreSQL repository for mail message metadata.

use tracing::warn;
use verifiable_storage::{ColumnQuery, Delete, StorageDatetime, StorageError, UnchainedRepository};
use verifiable_storage_postgres::{Order, PgPool, Query, QueryExecutor, Stored};

use kels_exchange::MailMessage;

#[derive(Stored)]
#[stored(item_type = MailMessage, table = "mail_messages", chained = false)]
pub struct MailMessageRepository {
    pub pool: PgPool,
}

impl MailMessageRepository {
    /// Store a mail message. Returns true if inserted, false if duplicate (idempotent).
    pub async fn store(&self, message: &MailMessage) -> Result<bool, StorageError> {
        match self.insert(message.clone()).await {
            Ok(_) => Ok(true),
            Err(StorageError::DuplicateRecord(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Fetch inbox for a recipient (paginated by created_at).
    pub async fn inbox(
        &self,
        recipient_kel_prefix: &cesr::Digest256,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MailMessage>, StorageError> {
        let query = Query::<MailMessage>::for_table(Self::TABLE_NAME)
            .eq("recipient_kel_prefix", recipient_kel_prefix.as_ref())
            .order_by("created_at", Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64);
        self.pool.fetch(query).await
    }

    /// Look up a message by SAID.
    pub async fn get_by_said(
        &self,
        said: &cesr::Digest256,
    ) -> Result<Option<MailMessage>, StorageError> {
        let query = Query::<MailMessage>::for_table(Self::TABLE_NAME)
            .eq("said", said.as_ref())
            .limit(1);
        self.pool.fetch_optional(query).await
    }

    /// Delete a message by SAID. Returns true if deleted.
    pub async fn delete(&self, said: &cesr::Digest256) -> Result<bool, StorageError> {
        let delete = Delete::<MailMessage>::for_table(Self::TABLE_NAME).eq("said", said.as_ref());
        let count = self.pool.delete(delete).await?;
        Ok(count > 0)
    }

    /// Delete expired messages in batches, returning (said, blob_digest) pairs.
    pub async fn delete_expired(
        &self,
    ) -> Result<Vec<(cesr::Digest256, cesr::Digest256)>, StorageError> {
        const BATCH_SIZE: u64 = 100;
        let now = StorageDatetime::now();
        let mut deleted = Vec::new();

        loop {
            let query = Query::<MailMessage>::for_table(Self::TABLE_NAME)
                .lt("expires_at", &now)
                .limit(BATCH_SIZE);
            let batch: Vec<MailMessage> = self.pool.fetch(query).await?;
            if batch.is_empty() {
                break;
            }

            for msg in &batch {
                match self.delete(&msg.said).await {
                    Ok(true) => deleted.push((msg.said, msg.blob_digest)),
                    Ok(false) => {}
                    Err(e) => warn!("Failed to delete expired message {}: {}", msg.said, e),
                }
            }
        }

        Ok(deleted)
    }

    /// Sum blob sizes for a recipient on a specific node (for local storage cap enforcement).
    pub async fn local_storage_for_recipient(
        &self,
        source_node_prefix: &cesr::Digest256,
        recipient_kel_prefix: &cesr::Digest256,
    ) -> Result<i64, StorageError> {
        let query = ColumnQuery::new(Self::TABLE_NAME, "blob_size")
            .eq("source_node_prefix", source_node_prefix.as_ref())
            .eq("recipient_kel_prefix", recipient_kel_prefix.as_ref());
        self.pool.sum(query).await
    }

    /// Count messages for a recipient (for inbox cap enforcement).
    pub async fn count_for_recipient(
        &self,
        recipient_kel_prefix: &cesr::Digest256,
    ) -> Result<usize, StorageError> {
        let query = Query::<MailMessage>::for_table(Self::TABLE_NAME)
            .eq("recipient_kel_prefix", recipient_kel_prefix.as_ref());
        let count = self.pool.count(query).await?;
        Ok(count as usize)
    }
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct MailRepository {
    pub messages: MailMessageRepository,
}
