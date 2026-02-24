//! SignedEventRepository trait - database-backed KEL storage

use async_trait::async_trait;

use crate::error::KelsError;

/// Implemented by repositories generated with `#[derive(SignedEvents)]`.
/// Wrap with `RepositoryKelStore` to use as `KelStore`.
#[async_trait]
pub trait SignedEventRepository: Send + Sync {
    /// Get a paginated page of signed events for a prefix.
    /// Returns `(events, has_more)`.
    async fn get_signed_history(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<crate::SignedKeyEvent>, bool), KelsError>;

    async fn get_signature_by_said(
        &self,
        said: &str,
    ) -> Result<Option<crate::EventSignature>, KelsError>;
    async fn create_with_signatures(
        &self,
        event: crate::KeyEvent,
        signatures: Vec<crate::EventSignature>,
    ) -> Result<crate::KeyEvent, KelsError>;

    /// Create multiple events with signatures in a single transaction.
    /// This ensures atomicity when saving multiple events (e.g., recovery + rotation).
    async fn create_batch_with_signatures(
        &self,
        events: Vec<(crate::KeyEvent, Vec<crate::EventSignature>)>,
    ) -> Result<(), KelsError>;
}
