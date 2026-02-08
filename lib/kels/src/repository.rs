//! SignedEventRepository trait - database-backed KEL storage

use async_trait::async_trait;

use crate::{error::KelsError, types::Kel};

/// Implemented by repositories generated with `#[stored(signed_events = true)]`.
/// Wrap with `RepositoryKelStore` to use as `KelStore`.
#[async_trait]
pub trait SignedEventRepository: Send + Sync {
    async fn get_kel(&self, prefix: &str) -> Result<Kel, KelsError>;
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
