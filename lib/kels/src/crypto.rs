//! Cryptographic Key Provider

use crate::error::KelsError;
use cesr::{PrivateKey, PublicKey, Signature, generate_secp256r1};
#[cfg(feature = "native")]
use std::sync::Arc;

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
use crate::hardware::HardwareKeyProvider;

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

    async fn prepare_recovery_rotation(&mut self) -> Result<(PublicKey, PublicKey), KelsError>;
    async fn commit_recovery_rotation(&mut self);
    async fn rollback_recovery_rotation(&mut self);
    async fn prepare_rotation(&mut self) -> Result<PublicKey, KelsError>;
    async fn pending_next_public_key(&self) -> Result<PublicKey, KelsError>;
    async fn sign_with_pending(&self, data: &[u8]) -> Result<Signature, KelsError>;
    async fn commit_rotation(&mut self);
    async fn rollback_rotation(&mut self);

    async fn current_handle(&self) -> Option<String> {
        None
    }
    async fn next_handle(&self) -> Option<String> {
        None
    }
    async fn recovery_handle(&self) -> Option<String> {
        None
    }
    async fn next_label_generation(&self) -> u64 {
        0
    }
}

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

    pub fn with_all_software_keys(
        current: Option<PrivateKey>,
        next: Option<PrivateKey>,
        recovery: Option<PrivateKey>,
    ) -> Self {
        Self::Software(Box::new(SoftwareKeyProvider::with_all_keys(
            current, next, recovery,
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
        current_label: Option<String>,
        next_label: Option<String>,
        recovery_label: Option<String>,
        next_label_generation: u64,
    ) -> Option<Self> {
        HardwareKeyProvider::with_all_handles(
            key_namespace,
            current_label,
            next_label,
            recovery_label,
            next_label_generation,
        )
        .map(|p| Self::Hardware(Box::new(p)))
    }

    #[cfg(feature = "native")]
    pub fn external(provider: Box<dyn ExternalKeyProvider>) -> Self {
        Self::External(Arc::new(tokio::sync::Mutex::new(provider)))
    }

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

    pub async fn generate_keypair(&mut self) -> Result<PublicKey, KelsError> {
        if !self.has_current().await {
            self.generate_into_current().await
        } else {
            self.generate_into_next().await
        }
    }

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

    async fn has_current(&self) -> bool {
        match self {
            Self::Software(p) => p.current_key.is_some(),
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
            Self::Software(p) => p.next_key.is_some(),
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

#[derive(Debug, Clone)]
pub struct SoftwareKeyProvider {
    current_key: Option<PrivateKey>,
    next_key: Option<PrivateKey>,
    recovery_key: Option<PrivateKey>,
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
            current_key: None,
            next_key: None,
            recovery_key: None,
            pending_next_key: None,
            pending_recovery_key: None,
        }
    }

    pub fn with_keys(current: PrivateKey, next: PrivateKey) -> Self {
        Self {
            current_key: Some(current),
            next_key: Some(next),
            recovery_key: None,
            pending_next_key: None,
            pending_recovery_key: None,
        }
    }

    pub fn with_all_keys(
        current: Option<PrivateKey>,
        next: Option<PrivateKey>,
        recovery: Option<PrivateKey>,
    ) -> Self {
        Self {
            current_key: current,
            next_key: next,
            recovery_key: recovery,
            pending_next_key: None,
            pending_recovery_key: None,
        }
    }

    pub fn current_private_key(&self) -> Option<&PrivateKey> {
        self.current_key.as_ref()
    }

    pub fn next_private_key(&self) -> Option<&PrivateKey> {
        self.next_key.as_ref()
    }

    pub fn recovery_private_key(&self) -> Option<&PrivateKey> {
        self.recovery_key.as_ref()
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
        // Current next will become current after commit
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
        // The "pending current" is the current next key
        let key = self.next_private_key().ok_or(KelsError::NoCurrentKey)?;
        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }

    /// Commit the prepared signing key rotation.
    /// Promotes next to current and moves pending_next to next.
    pub fn commit_rotation(&mut self) {
        if let Some(pending_next) = self.pending_next_key.take() {
            // next → current, pending_next → next
            self.current_key = self.next_key.take();
            self.next_key = Some(pending_next);
        }
    }

    /// Rollback a prepared signing key rotation (if KELS rejects).
    pub fn rollback_rotation(&mut self) {
        self.pending_next_key = None;
    }

    /// Generate a recovery key (called during inception).
    pub fn generate_recovery_key(&mut self) -> Result<PublicKey, KelsError> {
        let (public, private) = generate_secp256r1()?;
        self.recovery_key = Some(private);
        Ok(public)
    }

    // Primitive operations for KeyProvider enum delegation

    fn generate_into_current(&mut self) -> Result<PublicKey, KelsError> {
        let (public, private) = generate_secp256r1()?;
        self.current_key = Some(private);
        Ok(public)
    }

    fn generate_into_next(&mut self) -> Result<PublicKey, KelsError> {
        let (public, private) = generate_secp256r1()?;
        self.next_key = Some(private);
        Ok(public)
    }

    fn promote_next_to_current(&mut self) {
        self.current_key = self.next_key.take();
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

        // current_key = k0, next_key = k1
        assert_eq!(
            provider.current_public_key_sync().unwrap().qb64(),
            original_current.qb64()
        );
        assert_eq!(
            provider.next_public_key_sync().unwrap().qb64(),
            original_next.qb64()
        );

        // Prepare rotation: stages next → current and generates new next
        let prepared_current = provider.prepare_rotation_sync().unwrap();
        assert_eq!(prepared_current.qb64(), original_next.qb64());

        // Commit rotation: next → current, pending_next → next
        provider.commit_rotation();

        // After rotation: current = original_next, next = newly generated
        let new_current = provider.current_public_key_sync().unwrap();
        assert_eq!(new_current.qb64(), original_next.qb64());
        assert!(provider.next_public_key_sync().is_ok());
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
}
