//! Signed Event Repository trait
//!
//! Defines the `SignedEventRepository` trait for database-backed KEL storage.

use async_trait::async_trait;

use crate::error::KelsError;
use crate::kel::Kel;

/// Repository trait for storing signed key events with their signatures.
///
/// This trait is implemented by repositories generated with `#[stored(signed_events = true)]`.
/// It provides the methods needed for database-backed KEL storage.
///
/// Use `RepositoryKelStore` to wrap a `SignedEventRepository` as a `KelStore`.
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

    /// Save the SAID of the last event the owner created.
    /// Repositories that support owner tail tracking should store this in a table.
    async fn save_owner_tail(&self, _prefix: &str, _said: &str) -> Result<(), KelsError> {
        Ok(())
    }

    /// Load the owner's tail SAID.
    async fn load_owner_tail(&self, _prefix: &str) -> Result<Option<String>, KelsError> {
        Ok(None)
    }
}
