//! Repository-backed KEL store
//!
//! Provides `RepositoryKelStore` which wraps a `SignedEventRepository` as a `KelStore`.

use async_trait::async_trait;

use crate::error::KelsError;
use crate::kel::Kel;
use crate::repository::SignedEventRepository;
use crate::store::KelStore;

/// KelStore implementation backed by a SignedEventRepository.
///
/// Wraps any repository implementing `SignedEventRepository` to provide
/// `KelStore` functionality for use with `KeyEventBuilder`.
///
/// # Example
///
/// ```text
/// let repo = KeyEventRepository::new(pool);
/// let store = RepositoryKelStore::new(Arc::new(repo));
/// let builder = KeyEventBuilder::with_dependencies(key_provider, kels_client, Some(store), None);
/// ```
pub struct RepositoryKelStore<R: SignedEventRepository> {
    repo: std::sync::Arc<R>,
}

impl<R: SignedEventRepository> RepositoryKelStore<R> {
    pub fn new(repo: std::sync::Arc<R>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl<R: SignedEventRepository + 'static> KelStore for RepositoryKelStore<R> {
    async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError> {
        let kel = self.repo.get_kel(prefix).await?;
        if kel.is_empty() {
            Ok(None)
        } else {
            Ok(Some(kel))
        }
    }

    async fn save(&self, kel: &Kel) -> Result<(), KelsError> {
        // Save each event that isn't already in the database
        for signed_event in kel.events() {
            // Check if event already exists
            let existing = self
                .repo
                .get_signature_by_said(&signed_event.event.said)
                .await?;
            if existing.is_none() {
                if signed_event.signatures.is_empty() {
                    return Err(KelsError::NoCurrentKey);
                }
                self.repo
                    .create_with_signatures(
                        signed_event.event.clone(),
                        signed_event.event_signatures(),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn delete(&self, _prefix: &str) -> Result<(), KelsError> {
        Ok(())
    }

    async fn save_owner_tail(&self, prefix: &str, said: &str) -> Result<(), KelsError> {
        self.repo.save_owner_tail(prefix, said).await
    }

    async fn load_owner_tail(&self, prefix: &str) -> Result<Option<String>, KelsError> {
        self.repo.load_owner_tail(prefix).await
    }
}
