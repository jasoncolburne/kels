//! KEL Storage trait
//!
//! Defines the `KelStore` trait for persisting Key Event Logs.

use async_trait::async_trait;

use crate::error::KelsError;
use crate::kel::Kel;

/// Trait for persisting Key Event Logs locally.
///
/// Implementations can store KELs in files, databases, or other storage backends.
/// The `KeyEventBuilder` uses this trait to automatically persist KELs after
/// each successful operation.
///
/// # Owner Protection
///
/// When an `owner_prefix` is set, the `cache()` method will refuse to overwrite
/// KELs with that prefix. This protects the owner's authoritative local state
/// from being overwritten by data fetched from a server (which might include
/// adversary-injected events).
///
/// # Example
///
/// ```ignore
/// use kels::{FileKelStore, KelStore};
///
/// let store = FileKelStore::new("/path/to/kels")?;
///
/// // Save a KEL
/// store.save(&kel).await?;
///
/// // Load it back
/// if let Some(loaded) = store.load("prefix123").await? {
///     println!("Loaded KEL with {} events", loaded.len());
/// }
/// ```
#[async_trait]
pub trait KelStore: Send + Sync {
    /// The owner's prefix, if set.
    ///
    /// When set, the `cache()` method will skip saving KELs with this prefix
    /// to protect the owner's authoritative state from being overwritten by
    /// server fetches.
    fn owner_prefix(&self) -> Option<String> {
        None
    }

    /// Set or clear the owner prefix.
    ///
    /// Called after enrollment when the prefix becomes known, or on reset to clear it.
    /// Default implementation is a no-op for stores that don't support owner prefix.
    fn set_owner_prefix(&self, _prefix: Option<&str>) {}

    /// Load a KEL by its prefix.
    ///
    /// Returns `Ok(None)` if no KEL exists for the given prefix.
    /// The implementation should skip verification (pass `skip_verify: true` to
    /// `Kel::from_events`) since KELs are verified on save.
    async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError>;

    /// Save/persist a KEL.
    ///
    /// The KEL's prefix is used as the storage key.
    /// This should overwrite any existing KEL with the same prefix.
    async fn save(&self, kel: &Kel) -> Result<(), KelsError>;

    /// Delete a KEL by its prefix.
    ///
    /// Does nothing if the KEL doesn't exist.
    async fn delete(&self, prefix: &str) -> Result<(), KelsError>;

    /// Cache a KEL fetched from a server.
    ///
    /// If the KEL's prefix matches the owner prefix, this is a no-op to protect
    /// the owner's authoritative local state from being overwritten by server data.
    /// For other prefixes, this behaves like `save()`.
    async fn cache(&self, kel: &Kel) -> Result<(), KelsError> {
        if let Some(owner) = self.owner_prefix()
            && kel.prefix() == Some(owner.as_str())
        {
            return Ok(());
        }
        self.save(kel).await
    }

    /// Save the SAID of the last event the owner created.
    /// Used during recovery to identify which events in the divergent portion are ours
    /// vs the adversary's. Must be called before syncing with server.
    async fn save_owner_tail(&self, prefix: &str, said: &str) -> Result<(), KelsError>;

    /// Load the owner's tail SAID for tracing back through the owner's event chain.
    async fn load_owner_tail(&self, prefix: &str) -> Result<Option<String>, KelsError>;
}
