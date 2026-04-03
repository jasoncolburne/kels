//! PostgreSQL repository for mail message metadata.

use verifiable_storage::{Delete, StorageError, UnchainedRepository};
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
        recipient_kel_prefix: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MailMessage>, StorageError> {
        let query = Query::<MailMessage>::for_table(Self::TABLE_NAME)
            .eq("recipient_kel_prefix", recipient_kel_prefix)
            .order_by("created_at", Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64);
        self.pool.fetch(query).await
    }

    /// Look up a message by SAID.
    pub async fn get_by_said(&self, said: &str) -> Result<Option<MailMessage>, StorageError> {
        let query = Query::<MailMessage>::for_table(Self::TABLE_NAME)
            .eq("said", said)
            .limit(1);
        self.pool.fetch_optional(query).await
    }

    /// Delete a message by SAID. Returns true if deleted.
    pub async fn delete(&self, said: &str) -> Result<bool, StorageError> {
        let delete = Delete::<MailMessage>::for_table(Self::TABLE_NAME).eq("said", said);
        let count = self.pool.delete(delete).await?;
        Ok(count > 0)
    }

    /// Delete expired messages, returning the SAIDs of deleted messages.
    pub async fn delete_expired(&self) -> Result<Vec<String>, StorageError> {
        let now = chrono::Utc::now().to_rfc3339();
        let query = Query::<MailMessage>::for_table(Self::TABLE_NAME).lt("expires_at", &now);
        let expired: Vec<MailMessage> = self.pool.fetch(query).await?;
        let saids: Vec<String> = expired.iter().map(|m| m.said.clone()).collect();

        for said in &saids {
            let _ = self.delete(said).await;
        }

        Ok(saids)
    }

    /// Count messages for a recipient (for inbox cap enforcement).
    pub async fn count_for_recipient(
        &self,
        recipient_kel_prefix: &str,
    ) -> Result<usize, StorageError> {
        let query = Query::<MailMessage>::for_table(Self::TABLE_NAME)
            .eq("recipient_kel_prefix", recipient_kel_prefix);
        let messages: Vec<MailMessage> = self.pool.fetch(query).await?;
        Ok(messages.len())
    }
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct MailRepository {
    pub messages: MailMessageRepository,
}
