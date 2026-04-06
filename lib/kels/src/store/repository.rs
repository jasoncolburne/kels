//! RepositoryKelStore - wraps SignedEventRepository as KelStore

use async_trait::async_trait;

use super::KelStore;
use crate::{
    error::KelsError,
    repository::SignedEventRepository,
    types::{PagedKelSink, SignedKeyEvent},
};

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
    async fn load(
        &self,
        prefix: &cesr::Digest,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        self.repo
            .get_signed_history(prefix.as_ref(), limit, offset)
            .await
    }

    async fn load_tail(
        &self,
        prefix: &cesr::Digest,
        limit: u64,
    ) -> Result<Vec<SignedKeyEvent>, KelsError> {
        self.repo
            .get_signed_history_tail(prefix.as_ref(), limit)
            .await
    }

    async fn append(
        &self,
        prefix: &cesr::Digest,
        events: &[SignedKeyEvent],
    ) -> Result<(), KelsError> {
        self.repo.save_with_merge(prefix.as_ref(), events).await?;
        Ok(())
    }

    async fn overwrite(
        &self,
        prefix: &cesr::Digest,
        events: &[SignedKeyEvent],
    ) -> Result<(), KelsError> {
        self.repo.save_with_merge(prefix.as_ref(), events).await?;
        Ok(())
    }

    async fn delete(&self, _prefix: &cesr::Digest) -> Result<(), KelsError> {
        Ok(())
    }
}

#[async_trait]
impl<R: SignedEventRepository + 'static> PagedKelSink for RepositoryKelStore<R> {
    async fn store_page(&self, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        if events.is_empty() {
            return Ok(());
        }
        self.append(&events[0].event.prefix, events).await
    }
}
