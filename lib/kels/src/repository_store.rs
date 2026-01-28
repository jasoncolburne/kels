//! RepositoryKelStore - wraps SignedEventRepository as KelStore

use async_trait::async_trait;

use crate::error::KelsError;
use crate::kel::Kel;
use crate::repository::SignedEventRepository;
use crate::store::KelStore;

/// Wraps a SignedEventRepository to provide KelStore functionality.
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
        // Collect new events that need to be saved
        let mut new_events = Vec::new();
        for signed_event in kel.events() {
            if self
                .repo
                .get_signature_by_said(&signed_event.event.said)
                .await?
                .is_none()
            {
                if signed_event.signatures.is_empty() {
                    return Err(KelsError::NoCurrentKey);
                }
                new_events.push((signed_event.event.clone(), signed_event.event_signatures()));
            }
        }

        // Save all new events in a single transaction for atomicity
        if !new_events.is_empty() {
            self.repo.create_batch_with_signatures(new_events).await?;
        }
        Ok(())
    }

    async fn delete(&self, _prefix: &str) -> Result<(), KelsError> {
        Ok(())
    }
}
