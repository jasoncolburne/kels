//! SignedEventRepository trait - database-backed KEL storage

use async_trait::async_trait;

use crate::error::KelsError;
use crate::kel::Kel;

/// Implemented by repositories generated with `#[stored(signed_events = true)]`.
/// Wrap with `RepositoryKelStore` to use as `KelStore`.
#[async_trait]
pub trait SignedEventRepository: Send + Sync {
    async fn get_kel(&self, prefix: &str) -> Result<Kel, KelsError>;
    async fn get_signature_by_said(&self, said: &str) -> Result<Option<crate::EventSignature>, KelsError>;
    async fn create_with_signatures(&self, event: crate::KeyEvent, signatures: Vec<crate::EventSignature>) -> Result<crate::KeyEvent, KelsError>;

    /// Owner tail tracking for recovery
    async fn save_owner_tail(&self, _prefix: &str, _said: &str) -> Result<(), KelsError> { Ok(()) }
    async fn load_owner_tail(&self, _prefix: &str) -> Result<Option<String>, KelsError> { Ok(None) }
}
