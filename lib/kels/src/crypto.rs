//! Cryptographic Key Provider
//!
//! Provides a unified `KeyProvider` enum that abstracts over software and hardware
//! key storage. Business logic (slot management, rotation flow) lives in the enum,
//! while only primitive operations are delegated to the underlying implementations.

use crate::error::KelsError;
use cesr::{PrivateKey, PublicKey, Signature, generate_secp256r1};
#[cfg(feature = "native")]
use std::sync::Arc;

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
use crate::hardware::HardwareKeyProvider;

/// Trait for external key providers (HSM, etc.) that can be used with KeyProvider.
/// Only available on native platforms (requires tokio).
#[cfg(feature = "native")]
#[async_trait::async_trait]
pub trait ExternalKeyProvider: Send + Sync {
    async fn has_current(&self) -> bool;
    async fn has_next(&self) -> bool;
    async fn has_recovery(&self) -> bool;
    async fn generate_into_current(&mut self) -> Result<PublicKey, KelsError>;
    async fn generate_into_next(&mut self) -> Result<PublicKey, KelsError>;
    async fn generate_recovery_key(&mut self) -> Result<PublicKey, KelsError>;
    fn promote_next_to_current(&mut self);
    async fn current_public_key(&self) -> Result<PublicKey, KelsError>;
    async fn next_public_key(&self) -> Result<PublicKey, KelsError>;
    async fn recovery_public_key(&self) -> Result<PublicKey, KelsError>;
    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError>;
    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError>;
    async fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError>;

    /// Prepare recovery key rotation - generates new key but doesn't replace yet.
    /// Returns (current_recovery_pub, new_recovery_pub).
    async fn prepare_recovery_rotation(&mut self) -> Result<(PublicKey, PublicKey), KelsError>;

    /// Commit the prepared rotation - replaces current recovery key with new.
    async fn commit_recovery_rotation(&mut self);

    /// Rollback a prepared recovery key rotation (if KELS rejects).
    async fn rollback_recovery_rotation(&mut self);

    /// Prepare signing key rotation - stages next→current and generates new next.
    /// Returns the new current public key.
    async fn prepare_rotation(&mut self) -> Result<PublicKey, KelsError>;

    /// Get the pending next public key (after prepare_rotation).
    async fn pending_next_public_key(&self) -> Result<PublicKey, KelsError>;

    /// Sign with the pending current key (after prepare_rotation).
    async fn sign_with_pending(&self, data: &[u8]) -> Result<Signature, KelsError>;

    /// Commit the prepared signing key rotation.
    async fn commit_rotation(&mut self);

    /// Rollback a prepared signing key rotation (if KELS rejects).
    async fn rollback_rotation(&mut self);

    // Historical signing key methods for recovery at old versions

    /// Get the total number of signing keys (including current and next).
    async fn signing_handles_len(&self) -> usize;

    /// Sign with a signing key by generation index.
    /// Index 0 = inception key, Index N = key after N rotations.
    async fn sign_with_generation(
        &self,
        data: &[u8],
        generation: usize,
    ) -> Result<Signature, KelsError>;

    /// Truncate signing keys to keep only the first `keep_count` keys.
    /// Deletes removed keys from storage.
    async fn truncate_signing_keys(&mut self, keep_count: usize);

    // Handle/label methods for persistence (HSM, Secure Enclave)
    // Default implementations return None/empty for software-like providers

    /// Get all signing key labels (for persistence).
    async fn signing_labels(&self) -> Vec<String> {
        vec![]
    }

    /// Get the current key handle/label (for persistence).
    async fn current_handle(&self) -> Option<String> {
        None
    }

    /// Get the next key handle/label (for persistence).
    async fn next_handle(&self) -> Option<String> {
        None
    }

    /// Get the recovery key handle/label (for persistence).
    async fn recovery_handle(&self) -> Option<String> {
        None
    }

    /// Get the next label generation counter (for persistence).
    async fn next_label_generation(&self) -> u64 {
        0
    }
}

/// Unified key provider supporting software, hardware, and external key storage.
///
/// The enum contains business logic for key management while delegating
/// primitive operations (key generation, signing) to the underlying storage.
pub enum KeyProvider {
    Software(Box<SoftwareKeyProvider>),
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    Hardware(Box<HardwareKeyProvider>),
    #[cfg(feature = "native")]
    External(Arc<tokio::sync::Mutex<Box<dyn ExternalKeyProvider>>>),
}

impl KeyProvider {
    pub fn software() -> Self {
        Self::Software(Box::default())
    }

    pub fn with_software_keys(current: PrivateKey, next: PrivateKey) -> Self {
        Self::Software(Box::new(SoftwareKeyProvider::with_keys(current, next)))
    }

    /// Create with all software keys (for full restoration).
    /// `signing_keys` should contain all keys: historical + current + next
    pub fn with_all_software_keys(
        signing_keys: Vec<PrivateKey>,
        recovery: Option<PrivateKey>,
    ) -> Self {
        Self::Software(Box::new(SoftwareKeyProvider::with_all_keys(
            signing_keys,
            recovery,
        )))
    }

    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    pub fn hardware(key_namespace: &str) -> Option<Self> {
        HardwareKeyProvider::new(key_namespace).map(|p| Self::Hardware(Box::new(p)))
    }

    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    pub fn with_hardware_handles(
        key_namespace: &str,
        signing_labels: Vec<String>,
        recovery_label: Option<String>,
        next_label_generation: u64,
    ) -> Option<Self> {
        HardwareKeyProvider::with_all_handles(
            key_namespace,
            signing_labels,
            recovery_label,
            next_label_generation,
        )
        .map(|p| Self::Hardware(Box::new(p)))
    }

    #[cfg(feature = "native")]
    pub fn external(provider: Box<dyn ExternalKeyProvider>) -> Self {
        Self::External(Arc::new(tokio::sync::Mutex::new(provider)))
    }

    /// Try to clone this key provider.
    ///
    /// Only works for Software providers. Hardware and External providers
    /// cannot be cloned (returns None).
    ///
    /// Useful for creating independent key provider instances for testing
    /// (e.g., simulating an adversary with the same keys).
    pub async fn try_clone(&self) -> Option<Self> {
        match self {
            Self::Software(p) => Some(Self::Software(p.clone())),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => Some(Self::Hardware(Box::new(p.clone_async().await))),
            #[cfg(feature = "native")]
            Self::External(_) => None,
        }
    }

    /// Delete all keys (for decommission/reset).
    /// Only has effect for hardware keys - software keys are just dropped.
    pub async fn delete_all_keys(&mut self) {
        match self {
            Self::Software(_) => {
                // Software keys are just in memory, nothing to delete
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => {
                p.delete_all_keys().await;
            }
            #[cfg(feature = "native")]
            Self::External(_) => {
                // External providers manage their own key lifecycle
            }
        }
    }

    /// Get the current label generation (for cleanup tracking).
    /// Only meaningful for hardware keys.
    pub async fn current_generation(&self) -> u64 {
        match self {
            Self::Software(_) => 0,
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.current_generation().await,
            #[cfg(feature = "native")]
            Self::External(_) => 0,
        }
    }

    /// Delete keys created from start_generation up to current generation.
    /// Used to clean up keys created during adversarial injection.
    #[allow(unused_variables)]
    pub async fn delete_keys_from_generation(&self, start_generation: u64) {
        match self {
            Self::Software(_) => {
                // Software keys are just in memory, nothing to delete
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => {
                p.delete_keys_from_generation(start_generation).await;
            }
            #[cfg(feature = "native")]
            Self::External(_) => {
                // External providers manage their own key lifecycle
            }
        }
    }

    // === Business Logic (common across providers) ===

    /// Generate a new keypair, storing it in the first empty slot (current, then next).
    pub async fn generate_keypair(&mut self) -> Result<PublicKey, KelsError> {
        if !self.has_current().await {
            self.generate_into_current().await
        } else {
            self.generate_into_next().await
        }
    }

    /// Rotate keys: move next to current, generate new next.
    pub async fn rotate(&mut self) -> Result<PublicKey, KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoNextKey);
        }

        // Promote: next → current
        self.promote_next_to_current().await;
        // Generate new next key
        self.generate_into_next().await?;
        self.current_public_key().await
    }

    /// Generate a recovery key (called during inception).
    pub async fn generate_recovery_key(&mut self) -> Result<PublicKey, KelsError> {
        match self {
            Self::Software(p) => p.generate_recovery_key(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.generate_recovery_key().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.generate_recovery_key().await,
        }
    }

    /// Get the current public key.
    pub async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        match self {
            Self::Software(p) => p.current_public_key_sync(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.current_public_key().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.current_public_key().await,
        }
    }

    /// Get the next public key.
    pub async fn next_public_key(&self) -> Result<PublicKey, KelsError> {
        match self {
            Self::Software(p) => p.next_public_key_sync(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.next_public_key().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.next_public_key().await,
        }
    }

    /// Sign data with the current key.
    pub async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        match self {
            Self::Software(p) => p.sign_sync(data),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.sign(data).await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.sign(data).await,
        }
    }

    /// Sign data with the recovery key (for dual signatures during recovery events).
    pub async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        match self {
            Self::Software(p) => p.sign_with_recovery_sync(data),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.sign_with_recovery(data).await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.sign_with_recovery(data).await,
        }
    }

    /// Get the recovery public key.
    pub async fn recovery_public_key(&self) -> Result<PublicKey, KelsError> {
        match self {
            Self::Software(p) => p.recovery_public_key_sync(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.recovery_public_key().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.recovery_public_key().await,
        }
    }

    /// Prepare recovery key rotation - generates new key but doesn't replace yet.
    /// Returns (current_recovery_pub, new_recovery_pub).
    /// - current_recovery_pub goes in event's recovery_key field (revealed)
    /// - hash(new_recovery_pub) goes in event's recovery_hash field
    pub async fn prepare_recovery_rotation(&mut self) -> Result<(PublicKey, PublicKey), KelsError> {
        match self {
            Self::Software(p) => p.prepare_recovery_rotation_sync(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.prepare_recovery_rotation().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.prepare_recovery_rotation().await,
        }
    }

    /// Commit the prepared recovery rotation - replaces current recovery key with new.
    /// Must be called after prepare_recovery_rotation() and signing.
    pub async fn commit_recovery_rotation(&mut self) {
        match self {
            Self::Software(p) => p.commit_recovery_rotation(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.commit_recovery_rotation().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.commit_recovery_rotation().await,
        }
    }

    /// Rollback a prepared recovery key rotation (if KELS rejects).
    pub async fn rollback_recovery_rotation(&mut self) {
        match self {
            Self::Software(p) => p.rollback_recovery_rotation(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.rollback_recovery_rotation().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.rollback_recovery_rotation().await,
        }
    }

    /// Prepare signing key rotation - stages next→current and generates new next.
    /// Returns the new current public key.
    ///
    /// Does NOT modify the actual key state - call `commit_rotation()` after
    /// successful KELS submission, or call `rollback_rotation()` on failure.
    pub async fn prepare_rotation(&mut self) -> Result<PublicKey, KelsError> {
        match self {
            Self::Software(p) => p.prepare_rotation_sync(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.prepare_rotation().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.prepare_rotation().await,
        }
    }

    /// Get the pending next public key (after prepare_rotation).
    pub async fn pending_next_public_key(&self) -> Result<PublicKey, KelsError> {
        match self {
            Self::Software(p) => p.pending_next_public_key_sync(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.pending_next_public_key().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.pending_next_public_key().await,
        }
    }

    /// Sign with the pending current key (after prepare_rotation).
    pub async fn sign_with_pending(&self, data: &[u8]) -> Result<Signature, KelsError> {
        match self {
            Self::Software(p) => p.sign_with_pending_sync(data),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.sign_with_pending(data).await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.sign_with_pending(data).await,
        }
    }

    /// Commit the prepared signing key rotation.
    pub async fn commit_rotation(&mut self) {
        match self {
            Self::Software(p) => p.commit_rotation(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.commit_rotation().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.commit_rotation().await,
        }
    }

    /// Rollback a prepared signing key rotation (if KELS rejects).
    pub async fn rollback_rotation(&mut self) {
        match self {
            Self::Software(p) => p.rollback_rotation(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.rollback_rotation().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.rollback_rotation().await,
        }
    }

    /// Verify a signature using the current key.
    pub async fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError> {
        match self {
            Self::Software(p) => p.verify_sync(data, signature),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.verify(data, signature).await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.verify(data, signature).await,
        }
    }

    // === Signing key access methods ===

    /// Get the number of signing keys (including current and next).
    pub async fn signing_keys_len(&self) -> usize {
        match self {
            Self::Software(p) => p.signing_keys_len(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.signing_handles_len().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.signing_handles_len().await,
        }
    }

    /// Sign with a signing key by generation index.
    /// Index 0 = inception key, Index N = key after N rotations.
    pub async fn sign_with_generation(
        &self,
        data: &[u8],
        generation: usize,
    ) -> Result<Signature, KelsError> {
        match self {
            Self::Software(p) => p.sign_with_generation(data, generation),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.sign_with_generation(data, generation).await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.sign_with_generation(data, generation).await,
        }
    }

    /// Truncate signing keys to keep only the first `keep_count` keys.
    pub async fn truncate_signing_keys(&mut self, keep_count: usize) {
        match self {
            Self::Software(p) => p.truncate_signing_keys(keep_count),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.truncate_signing_keys(keep_count).await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.truncate_signing_keys(keep_count).await,
        }
    }

    // === Primitive Operations (delegated to providers) ===

    async fn has_current(&self) -> bool {
        match self {
            // Current exists if we have at least 1 key
            Self::Software(p) => !p.signing_keys.is_empty(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.has_current().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.has_current().await,
        }
    }

    async fn has_next(&self) -> bool {
        match self {
            // Next is at len-1, so need at least 2 keys
            Self::Software(p) => p.signing_keys.len() >= 2,
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.has_next().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.has_next().await,
        }
    }

    async fn generate_into_current(&mut self) -> Result<PublicKey, KelsError> {
        match self {
            Self::Software(p) => p.generate_into_current(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.generate_into_current().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.generate_into_current().await,
        }
    }

    async fn generate_into_next(&mut self) -> Result<PublicKey, KelsError> {
        match self {
            Self::Software(p) => p.generate_into_next(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.generate_into_next().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.generate_into_next().await,
        }
    }

    async fn promote_next_to_current(&mut self) {
        match self {
            Self::Software(p) => p.promote_next_to_current(),
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.promote_next_to_current(),
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.promote_next_to_current(),
        }
    }

    // === Accessors for provider-specific state ===

    #[allow(unreachable_patterns)]
    pub fn as_software(&self) -> Option<&SoftwareKeyProvider> {
        match self {
            Self::Software(p) => Some(p),
            _ => None,
        }
    }

    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    #[allow(unreachable_patterns)]
    pub fn as_hardware(&self) -> Option<&HardwareKeyProvider> {
        match self {
            Self::Hardware(p) => Some(p),
            _ => None,
        }
    }

    // === Handle/label accessors for persistence ===

    /// Get the current key handle/label (for persistence).
    pub async fn current_handle(&self) -> Option<String> {
        match self {
            Self::Software(_) => None,
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.current_label().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.current_handle().await,
        }
    }

    /// Get the next key handle/label (for persistence).
    pub async fn next_handle(&self) -> Option<String> {
        match self {
            Self::Software(_) => None,
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.next_label().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.next_handle().await,
        }
    }

    /// Get the recovery key handle/label (for persistence).
    pub async fn recovery_handle(&self) -> Option<String> {
        match self {
            Self::Software(_) => None,
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.recovery_label().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.recovery_handle().await,
        }
    }

    /// Get the next label generation counter (for persistence).
    pub async fn next_label_generation(&self) -> u64 {
        match self {
            Self::Software(_) => 0,
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "secure-enclave"
            ))]
            Self::Hardware(p) => p.next_label_generation().await,
            #[cfg(feature = "native")]
            Self::External(p) => p.lock().await.next_label_generation().await,
        }
    }
}

/// Software-based key provider using in-memory keys.
///
/// Key structure:
/// - `signing_keys`: All signing keys in a single Vec
///   - Index 0..len-2: Historical keys (previous signing keys)
///   - Index len-2: Current signing key
///   - Index len-1: Next key (pre-committed)
/// - `recovery_key`: Recovery key (hash in recovery_hash, never revealed except in rec/ror)
///
/// Transient keys for two-phase rotation:
/// - `pending_next_key`: New next key being staged during rotation
/// - `pending_recovery_key`: New recovery key being staged during recovery rotation
#[derive(Debug, Clone)]
pub struct SoftwareKeyProvider {
    /// All signing keys: historical (0..len-2), current (len-2), next (len-1)
    signing_keys: Vec<PrivateKey>,
    recovery_key: Option<PrivateKey>,
    // Pending keys for two-phase rotation
    pending_next_key: Option<PrivateKey>,
    pending_recovery_key: Option<PrivateKey>,
}

impl Default for SoftwareKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareKeyProvider {
    pub fn new() -> Self {
        Self {
            signing_keys: Vec::new(),
            recovery_key: None,
            pending_next_key: None,
            pending_recovery_key: None,
        }
    }

    pub fn with_keys(current: PrivateKey, next: PrivateKey) -> Self {
        Self {
            signing_keys: vec![current, next],
            recovery_key: None,
            pending_next_key: None,
            pending_recovery_key: None,
        }
    }

    /// Create with all signing keys and optional recovery key (for full restoration).
    /// `signing_keys` should contain all keys: historical + current + next
    pub fn with_all_keys(signing_keys: Vec<PrivateKey>, recovery: Option<PrivateKey>) -> Self {
        Self {
            signing_keys,
            recovery_key: recovery,
            pending_next_key: None,
            pending_recovery_key: None,
        }
    }

    /// Get the current signing key.
    /// - len == 0: None
    /// - len == 1: index 0 (inception, next not yet generated)
    /// - len >= 2: index len-2
    pub fn current_private_key(&self) -> Option<&PrivateKey> {
        match self.signing_keys.len() {
            0 => None,
            1 => self.signing_keys.first(),
            n => self.signing_keys.get(n - 2),
        }
    }

    /// Get the next (pre-committed) key (at index len-1).
    /// Only valid when len >= 2.
    pub fn next_private_key(&self) -> Option<&PrivateKey> {
        if self.signing_keys.len() >= 2 {
            self.signing_keys.last()
        } else {
            None
        }
    }

    pub fn recovery_private_key(&self) -> Option<&PrivateKey> {
        self.recovery_key.as_ref()
    }

    pub fn signing_keys(&self) -> &[PrivateKey] {
        &self.signing_keys
    }

    pub fn current_public_key_sync(&self) -> Result<PublicKey, KelsError> {
        self.current_private_key()
            .map(|k| k.public_key())
            .ok_or(KelsError::NoCurrentKey)
    }

    pub fn next_public_key_sync(&self) -> Result<PublicKey, KelsError> {
        self.next_private_key()
            .map(|k| k.public_key())
            .ok_or(KelsError::NoNextKey)
    }

    pub fn recovery_public_key_sync(&self) -> Result<PublicKey, KelsError> {
        self.recovery_key
            .as_ref()
            .map(|k| k.public_key())
            .ok_or(KelsError::NoRecoveryKey)
    }

    pub fn sign_sync(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let key = self.current_private_key().ok_or(KelsError::NoCurrentKey)?;
        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }

    pub fn sign_with_recovery_sync(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let key = self.recovery_key.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }

    fn verify_sync(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError> {
        let public_key = self.current_public_key_sync()?;
        public_key
            .verify(data, signature)
            .map_err(|e| KelsError::VerificationFailed(e.to_string()))
    }

    /// Prepare recovery key rotation - generates new key but doesn't replace yet.
    /// Returns (current_recovery_pub, new_recovery_pub).
    /// - current_recovery_pub goes in event's recovery_key field (revealed)
    /// - hash(new_recovery_pub) goes in event's recovery_hash field
    pub fn prepare_recovery_rotation_sync(&mut self) -> Result<(PublicKey, PublicKey), KelsError> {
        let current_recovery = self
            .recovery_key
            .as_ref()
            .ok_or(KelsError::NoRecoveryKey)?
            .public_key();

        let (new_recovery_pub, new_recovery_priv) = generate_secp256r1()?;
        self.pending_recovery_key = Some(new_recovery_priv);

        Ok((current_recovery, new_recovery_pub))
    }

    /// Commit the prepared rotation - replaces current recovery key with new.
    /// Must be called after prepare_recovery_rotation() and signing.
    pub fn commit_recovery_rotation(&mut self) {
        if let Some(pending) = self.pending_recovery_key.take() {
            self.recovery_key = Some(pending);
        }
    }

    /// Rollback a prepared recovery key rotation (if KELS rejects).
    pub fn rollback_recovery_rotation(&mut self) {
        self.pending_recovery_key = None;
    }

    /// Prepare signing key rotation - generates new next key.
    /// Returns the new current public key (what will be current after commit).
    pub fn prepare_rotation_sync(&mut self) -> Result<PublicKey, KelsError> {
        // Current next (at len-1) will become current after commit
        let new_current_pub = self
            .next_private_key()
            .ok_or(KelsError::NoNextKey)?
            .public_key();

        // Generate new next key into pending slot
        let (_new_next_pub, new_next_priv) = generate_secp256r1()?;
        self.pending_next_key = Some(new_next_priv);

        Ok(new_current_pub)
    }

    /// Get the pending next public key (after prepare_rotation).
    pub fn pending_next_public_key_sync(&self) -> Result<PublicKey, KelsError> {
        self.pending_next_key
            .as_ref()
            .map(|k| k.public_key())
            .ok_or(KelsError::NoNextKey)
    }

    /// Sign with the pending current key (after prepare_rotation).
    /// This signs with the current next key, which will become current after commit.
    pub fn sign_with_pending_sync(&self, data: &[u8]) -> Result<Signature, KelsError> {
        // The "pending current" is the current next key (at len-1)
        let key = self.next_private_key().ok_or(KelsError::NoCurrentKey)?;
        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }

    /// Commit the prepared signing key rotation.
    /// Pushes pending_next_key to signing_keys, making current next become current.
    pub fn commit_rotation(&mut self) {
        if let Some(pending_next) = self.pending_next_key.take() {
            self.signing_keys.push(pending_next);
        }
    }

    /// Rollback a prepared signing key rotation (if KELS rejects).
    pub fn rollback_rotation(&mut self) {
        // Just discard pending next
        self.pending_next_key = None;
    }

    /// Generate a recovery key (called during inception).
    pub fn generate_recovery_key(&mut self) -> Result<PublicKey, KelsError> {
        let (public, private) = generate_secp256r1()?;
        self.recovery_key = Some(private);
        Ok(public)
    }

    // Primitive operations for KeyProvider enum delegation

    /// Generate a key and push to signing_keys. Used during inception.
    fn generate_into_current(&mut self) -> Result<PublicKey, KelsError> {
        let (public, private) = generate_secp256r1()?;
        self.signing_keys.push(private);
        Ok(public)
    }

    /// Generate a key and push to signing_keys. Used during inception.
    fn generate_into_next(&mut self) -> Result<PublicKey, KelsError> {
        let (public, private) = generate_secp256r1()?;
        self.signing_keys.push(private);
        Ok(public)
    }

    fn promote_next_to_current(&mut self) {
        // No-op with unified signing_keys - rotation just pushes new key
    }

    // === Signing key access methods ===

    /// Get the number of signing keys (including current and next).
    /// After N rotations, this returns N+2 (inception + N rotations + next).
    pub fn signing_keys_len(&self) -> usize {
        self.signing_keys.len()
    }

    /// Get a signing key by generation index.
    /// Index 0 = inception key, Index N = key after N rotations.
    /// Index len-2 = current, Index len-1 = next.
    pub fn signing_key(&self, index: usize) -> Option<&PrivateKey> {
        self.signing_keys.get(index)
    }

    /// Get the public key at a specific generation.
    pub fn public_key_at_generation(&self, generation: usize) -> Result<PublicKey, KelsError> {
        let key = self
            .signing_keys
            .get(generation)
            .ok_or(KelsError::NoHistoricalKey(generation))?;
        Ok(key.public_key())
    }

    /// Sign with a signing key by generation index.
    /// Index 0 = inception key, Index N = key after N rotations.
    pub fn sign_with_generation(&self, data: &[u8], index: usize) -> Result<Signature, KelsError> {
        let key = self
            .signing_keys
            .get(index)
            .ok_or(KelsError::NoHistoricalKey(index))?;
        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }

    /// Truncate signing keys to keep only the first `keep_count` keys.
    /// Used after successful recovery to discard keys no longer needed.
    pub fn truncate_signing_keys(&mut self, keep_count: usize) {
        self.signing_keys.truncate(keep_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::Matter;

    #[test]
    fn test_software_provider_generate() {
        let mut provider = SoftwareKeyProvider::new();

        let current = provider.generate_into_current().unwrap();
        assert!(provider.current_public_key_sync().is_ok());
        assert!(provider.next_public_key_sync().is_err());

        let next = provider.generate_into_next().unwrap();
        assert!(provider.next_public_key_sync().is_ok());

        assert_ne!(current.qb64(), next.qb64());
    }

    #[test]
    fn test_software_provider_sign() {
        let mut provider = SoftwareKeyProvider::new();
        provider.generate_into_current().unwrap();

        let message = b"test message";
        let signature = provider.sign_sync(message).unwrap();

        let public = provider.current_public_key_sync().unwrap();
        assert!(public.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_software_provider_rotate_primitives() {
        let mut provider = SoftwareKeyProvider::new();

        let original_current = provider.generate_into_current().unwrap();
        let original_next = provider.generate_into_next().unwrap();

        // signing_keys = [k0, k1] where k0=current (len-2=0), k1=next (len-1=1)
        assert_eq!(
            provider.current_public_key_sync().unwrap().qb64(),
            original_current.qb64()
        );
        assert_eq!(
            provider.next_public_key_sync().unwrap().qb64(),
            original_next.qb64()
        );

        // Simulate full rotation: generate new key (this shifts indices)
        let new_next = provider.generate_into_next().unwrap();

        // signing_keys = [k0, k1, k2] where k1=current (len-2=1), k2=next (len-1=2)
        let new_current = provider.current_public_key_sync().unwrap();
        assert_eq!(new_current.qb64(), original_next.qb64());
        assert_eq!(
            provider.next_public_key_sync().unwrap().qb64(),
            new_next.qb64()
        );
    }

    #[test]
    fn test_software_provider_recovery_key() {
        let mut provider = SoftwareKeyProvider::new();

        // Initially no recovery key
        assert!(provider.recovery_public_key_sync().is_err());

        // Generate recovery key
        let recovery = provider.generate_recovery_key().unwrap();
        assert!(provider.recovery_public_key_sync().is_ok());
        assert_eq!(
            provider.recovery_public_key_sync().unwrap().qb64(),
            recovery.qb64()
        );

        // Sign with recovery key
        let message = b"test message";
        let sig = provider.sign_with_recovery_sync(message).unwrap();
        assert!(recovery.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_software_provider_recovery_rotation() {
        let mut provider = SoftwareKeyProvider::new();

        // Generate initial recovery key
        let original_recovery = provider.generate_recovery_key().unwrap();

        // Prepare recovery rotation
        let (current_recovery, new_recovery) = provider.prepare_recovery_rotation_sync().unwrap();
        assert_eq!(current_recovery.qb64(), original_recovery.qb64());
        assert_ne!(new_recovery.qb64(), original_recovery.qb64());

        // Before commit, recovery key is still the original
        assert_eq!(
            provider.recovery_public_key_sync().unwrap().qb64(),
            original_recovery.qb64()
        );

        // Commit the rotation
        provider.commit_recovery_rotation();

        // After commit, recovery key is the new one
        assert_eq!(
            provider.recovery_public_key_sync().unwrap().qb64(),
            new_recovery.qb64()
        );
    }

    #[test]
    fn test_software_provider_with_keys() {
        let (pub1, priv1) = generate_secp256r1().unwrap();
        let (pub2, priv2) = generate_secp256r1().unwrap();

        let provider = SoftwareKeyProvider::with_keys(priv1, priv2);

        assert_eq!(
            provider.current_public_key_sync().unwrap().qb64(),
            pub1.qb64()
        );
        assert_eq!(provider.next_public_key_sync().unwrap().qb64(), pub2.qb64());
    }

    #[test]
    fn test_sign_without_key_fails() {
        let provider = SoftwareKeyProvider::new();
        assert!(provider.sign_sync(b"test").is_err());
    }

    #[tokio::test]
    async fn test_key_provider_enum_generate() {
        let mut provider = KeyProvider::software();

        let current = provider.generate_keypair().await.unwrap();
        assert!(provider.current_public_key().await.is_ok());
        assert!(provider.next_public_key().await.is_err());

        let next = provider.generate_keypair().await.unwrap();
        assert!(provider.next_public_key().await.is_ok());

        assert_ne!(current.qb64(), next.qb64());
    }

    #[tokio::test]
    async fn test_key_provider_enum_rotate() {
        let mut provider = KeyProvider::software();

        let _current = provider.generate_keypair().await.unwrap();
        let original_next = provider.generate_keypair().await.unwrap();

        let new_current = provider.rotate().await.unwrap();
        assert_eq!(new_current.qb64(), original_next.qb64());

        // Should have a new next key after rotation
        assert!(provider.next_public_key().await.is_ok());
    }

    #[tokio::test]
    async fn test_key_provider_enum_rotate_without_next_fails() {
        let mut provider = KeyProvider::software();
        provider.generate_keypair().await.unwrap();
        assert!(provider.rotate().await.is_err());
    }

    #[test]
    fn test_software_provider_signing_keys() {
        let mut provider = SoftwareKeyProvider::new();

        // Initially no keys
        assert_eq!(provider.signing_keys_len(), 0);

        // Generate inception keys (current + next)
        let inception_pub = provider.generate_into_current().unwrap();
        provider.generate_into_next().unwrap();
        provider.generate_recovery_key().unwrap();

        // Now have 2 keys: current (index 0) and next (index 1)
        assert_eq!(provider.signing_keys_len(), 2);

        // Prepare and commit first rotation
        provider.prepare_rotation_sync().unwrap();
        provider.commit_rotation();

        // Now have 3 keys: inception (0), rot1=current (1), next (2)
        assert_eq!(provider.signing_keys_len(), 3);

        // Sign with inception key (generation 0)
        let message = b"test message";
        let sig = provider.sign_with_generation(message, 0).unwrap();
        assert!(inception_pub.verify(message, &sig).is_ok());

        // Second rotation
        let second_key_pub = provider.current_public_key_sync().unwrap();
        provider.prepare_rotation_sync().unwrap();
        provider.commit_rotation();

        // Now have 4 keys: inception (0), rot1 (1), rot2=current (2), next (3)
        assert_eq!(provider.signing_keys_len(), 4);

        // Can sign with both historical generations
        let sig0 = provider.sign_with_generation(message, 0).unwrap();
        let sig1 = provider.sign_with_generation(message, 1).unwrap();
        assert!(inception_pub.verify(message, &sig0).is_ok());
        assert!(second_key_pub.verify(message, &sig1).is_ok());

        // Truncate to keep only first 2 keys
        provider.truncate_signing_keys(2);
        assert_eq!(provider.signing_keys_len(), 2);

        // Can still sign with first two keys
        assert!(provider.sign_with_generation(message, 0).is_ok());
        assert!(provider.sign_with_generation(message, 1).is_ok());
        // But not third
        assert!(provider.sign_with_generation(message, 2).is_err());
    }
}
