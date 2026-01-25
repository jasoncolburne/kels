//! KEL Storage trait - persisting Key Event Logs locally

use async_trait::async_trait;

use crate::error::KelsError;
use crate::kel::Kel;

/// Trait for persisting KELs. When `owner_prefix` is set, `cache()` protects the owner's
/// authoritative state from being overwritten by server-fetched data.
#[async_trait]
pub trait KelStore: Send + Sync {
    /// Owner's prefix. When set, `cache()` skips saving KELs with this prefix.
    fn owner_prefix(&self) -> Option<String> {
        None
    }

    /// Set/clear owner prefix after enrollment.
    fn set_owner_prefix(&self, _prefix: Option<&str>) {}

    /// Load a KEL by prefix. Returns None if not found. Skip verification on load (verified on save).
    async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError>;

    /// Save a KEL, overwriting any existing one with the same prefix.
    async fn save(&self, kel: &Kel) -> Result<(), KelsError>;

    /// Delete a KEL by prefix. No-op if not found.
    async fn delete(&self, prefix: &str) -> Result<(), KelsError>;

    /// Cache server-fetched KEL. Skips owner prefix to protect authoritative local state.
    async fn cache(&self, kel: &Kel) -> Result<(), KelsError> {
        if let Some(owner) = self.owner_prefix()
            && kel.prefix() == Some(owner.as_str())
        {
            return Ok(());
        }
        self.save(kel).await
    }
}
