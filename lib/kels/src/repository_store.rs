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
