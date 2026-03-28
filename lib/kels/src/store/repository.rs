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
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        self.repo.get_signed_history(prefix, limit, offset).await
    }

    async fn load_tail(&self, prefix: &str, limit: u64) -> Result<Vec<SignedKeyEvent>, KelsError> {
        self.repo.get_signed_history_tail(prefix, limit).await
    }

    async fn append(&self, prefix: &str, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        self.repo.save_with_merge(prefix, events).await?;
        Ok(())
    }

    async fn overwrite(&self, prefix: &str, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        self.repo.save_with_merge(prefix, events).await?;
        Ok(())
    }

    async fn delete(&self, _prefix: &str) -> Result<(), KelsError> {
        Ok(())
    }
}

#[async_trait]
impl<R: SignedEventRepository + 'static> PagedKelSink for RepositoryKelStore<R> {
    async fn store_page(&self, prefix: &str, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        self.append(prefix, events).await
    }
}
