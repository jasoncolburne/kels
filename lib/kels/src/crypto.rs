//! Cryptographic Key Provider

use crate::error::KelsError;
use cesr::{PrivateKey, PublicKey, Signature, generate_secp256r1};
use std::path::{Path, PathBuf};

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
use crate::hardware::HardwareKeyProvider;

// ==================== ProviderConfig Trait ====================

/// Trait for provider configuration that handles creation and persistence.
pub trait ProviderConfig: Send + Sync {
    /// The provider type this config creates.
    type Provider: KeyProvider;

    /// Loads or creates a provider from this configuration.
    fn load_provider(&self) -> Result<Self::Provider, KelsError>;

    /// Saves the provider state.
    fn save_provider(&self, provider: &Self::Provider) -> Result<(), KelsError>;
}

/// Software provider configuration - keys stored in files.
#[derive(Debug, Clone)]
pub struct SoftwareProviderConfig {
    pub key_dir: PathBuf,
}

impl SoftwareProviderConfig {
    pub fn new(key_dir: PathBuf) -> Self {
        Self { key_dir }
    }
}

impl ProviderConfig for SoftwareProviderConfig {
    type Provider = SoftwareKeyProvider;

    fn load_provider(&self) -> Result<Self::Provider, KelsError> {
        if self.key_dir.exists() {
            SoftwareKeyProvider::load_from_dir(&self.key_dir)
        } else {
            Ok(SoftwareKeyProvider::new())
        }
    }

    fn save_provider(&self, provider: &Self::Provider) -> Result<(), KelsError> {
        provider.save_to_dir(&self.key_dir)
    }
}

/// Hardware provider configuration - keys in Secure Enclave.
#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
#[derive(Debug, Clone)]
pub struct HardwareProviderConfig {
    pub namespace: String,
}

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
impl HardwareProviderConfig {
    pub fn new(namespace: String) -> Self {
        Self { namespace }
    }
}

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
impl ProviderConfig for HardwareProviderConfig {
    type Provider = HardwareKeyProvider;

    fn load_provider(&self) -> Result<Self::Provider, KelsError> {
        HardwareKeyProvider::new(&self.namespace)
            .ok_or_else(|| KelsError::HardwareError("Secure Enclave not available".into()))
    }

    fn save_provider(&self, _provider: &Self::Provider) -> Result<(), KelsError> {
        // Hardware keys persist automatically in the Secure Enclave
        Ok(())
    }
}

// ==================== KeyProvider Trait ====================

/// Trait for cryptographic key management and signing operations.
///
/// Implementations manage three key slots:
/// - **current**: The active signing key
/// - **next**: Pre-committed key for the next rotation (rotation hash published)
/// - **recovery**: Emergency key for recovery operations
///
/// Rotation is a two-phase operation:
/// 1. `prepare_rotation()` - stages the rotation (next becomes pending current, new next generated)
/// 2. `commit_rotation()` or `rollback_rotation()` - finalizes or reverts
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    // ==================== Accessors ====================

    /// Returns the handle/label for the current key (for persistence).
    async fn current_handle(&self) -> Option<String> {
        None
    }

    /// Returns the current signing public key.
    async fn current_public_key(&self) -> Result<PublicKey, KelsError>;

    /// Returns the handle/label for the next key (for persistence).
    async fn next_handle(&self) -> Option<String> {
        None
    }

    /// Returns the generation counter for key labels (for persistence).
    async fn next_label_generation(&self) -> u64 {
        0
    }

    /// Returns the next (pre-committed) public key.
    async fn next_public_key(&self) -> Result<PublicKey, KelsError>;

    /// Returns the staged next public key (after prepare_rotation, before commit).
    async fn pending_next_public_key(&self) -> Result<PublicKey, KelsError>;

    /// Returns the handle/label for the recovery key (for persistence).
    async fn recovery_handle(&self) -> Option<String> {
        None
    }

    /// Returns the recovery public key.
    async fn recovery_public_key(&self) -> Result<PublicKey, KelsError>;

    // ==================== Key Generation ====================

    /// Generates a new key into the current slot.
    async fn generate_into_current(&mut self) -> Result<PublicKey, KelsError>;

    /// Generates a new key into the next slot.
    async fn generate_into_next(&mut self) -> Result<PublicKey, KelsError>;

    /// Generates a new recovery key.
    async fn generate_recovery_key(&mut self) -> Result<PublicKey, KelsError>;

    // ==================== Query Methods ====================

    /// Returns true if a current key exists.
    async fn has_current(&self) -> bool;

    /// Returns true if a next key exists.
    async fn has_next(&self) -> bool;

    /// Returns true if a recovery key exists.
    async fn has_recovery(&self) -> bool;

    // ==================== Rotation Operations ====================

    /// Commits a staged recovery key rotation.
    async fn commit_recovery_rotation(&mut self);

    /// Commits a staged key rotation (pending becomes active).
    async fn commit_rotation(&mut self);

    /// Prepares a recovery key rotation. Returns (current_recovery_pub, new_recovery_pub).
    async fn prepare_recovery_rotation(&mut self) -> Result<(PublicKey, PublicKey), KelsError>;

    /// Prepares a key rotation. Returns the new current public key (what next will become).
    async fn prepare_rotation(&mut self) -> Result<PublicKey, KelsError>;

    /// Reverts a staged recovery key rotation.
    async fn rollback_recovery_rotation(&mut self);

    /// Reverts a staged key rotation.
    async fn rollback_rotation(&mut self);

    // ==================== Signing ====================

    /// Signs data with the current key.
    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError>;

    /// Signs data with the pending current key (next key, used during rotation).
    async fn sign_with_pending(&self, data: &[u8]) -> Result<Signature, KelsError>;

    /// Signs data with the recovery key.
    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError>;

    /// Verifies a signature against the current public key.
    async fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError>;

    // ==================== Convenience Methods ====================

    /// Generates a keypair into the appropriate slot (current if empty, else next).
    async fn generate_keypair(&mut self) -> Result<PublicKey, KelsError> {
        if !self.has_current().await {
            self.generate_into_current().await
        } else {
            self.generate_into_next().await
        }
    }
}

// ==================== SoftwareKeyProvider ====================

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
    // ==================== Constructors ====================

    pub fn new() -> Self {
        Self {
            current_key: None,
            next_key: None,
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

    pub fn with_keys(current: PrivateKey, next: PrivateKey) -> Self {
        Self {
            current_key: Some(current),
            next_key: Some(next),
            recovery_key: None,
            pending_next_key: None,
            pending_recovery_key: None,
        }
    }
}

// Persistence methods
impl SoftwareKeyProvider {
    /// Loads keys from a directory containing key files.
    pub fn load_from_dir(dir: &Path) -> Result<Self, KelsError> {
        let current_path = dir.join("current.key");
        let next_path = dir.join("next.key");
        let recovery_path = dir.join("recovery.key");

        let current = if current_path.exists() {
            let qb64 = std::fs::read_to_string(&current_path).map_err(|e| {
                KelsError::HardwareError(format!("Failed to read current key: {}", e))
            })?;
            Some(PrivateKey::from_qb64(qb64.trim())?)
        } else {
            None
        };

        let next = if next_path.exists() {
            let qb64 = std::fs::read_to_string(&next_path)
                .map_err(|e| KelsError::HardwareError(format!("Failed to read next key: {}", e)))?;
            Some(PrivateKey::from_qb64(qb64.trim())?)
        } else {
            None
        };

        let recovery = if recovery_path.exists() {
            let qb64 = std::fs::read_to_string(&recovery_path).map_err(|e| {
                KelsError::HardwareError(format!("Failed to read recovery key: {}", e))
            })?;
            Some(PrivateKey::from_qb64(qb64.trim())?)
        } else {
            None
        };

        Ok(Self::with_all_keys(current, next, recovery))
    }

    /// Saves keys to a directory.
    pub fn save_to_dir(&self, dir: &Path) -> Result<(), KelsError> {
        std::fs::create_dir_all(dir).map_err(|e| {
            KelsError::HardwareError(format!("Failed to create key directory: {}", e))
        })?;

        if let Some(key) = &self.current_key {
            let path = dir.join("current.key");
            std::fs::write(&path, key.qb64()).map_err(|e| {
                KelsError::HardwareError(format!("Failed to write current key: {}", e))
            })?;
        }

        if let Some(key) = &self.next_key {
            let path = dir.join("next.key");
            std::fs::write(&path, key.qb64()).map_err(|e| {
                KelsError::HardwareError(format!("Failed to write next key: {}", e))
            })?;
        }

        if let Some(key) = &self.recovery_key {
            let path = dir.join("recovery.key");
            std::fs::write(&path, key.qb64()).map_err(|e| {
                KelsError::HardwareError(format!("Failed to write recovery key: {}", e))
            })?;
        }

        Ok(())
    }
}

// Test-only private key accessors
#[cfg(test)]
impl SoftwareKeyProvider {
    pub fn current_private_key(&self) -> Option<&PrivateKey> {
        self.current_key.as_ref()
    }

    pub fn next_private_key(&self) -> Option<&PrivateKey> {
        self.next_key.as_ref()
    }
}

// ==================== KeyProvider impl for SoftwareKeyProvider ====================

#[async_trait::async_trait]
impl KeyProvider for SoftwareKeyProvider {
    async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        self.current_key
            .as_ref()
            .map(|k| k.public_key())
            .ok_or(KelsError::NoCurrentKey)
    }

    async fn next_public_key(&self) -> Result<PublicKey, KelsError> {
        self.next_key
            .as_ref()
            .map(|k| k.public_key())
            .ok_or(KelsError::NoNextKey)
    }

    async fn pending_next_public_key(&self) -> Result<PublicKey, KelsError> {
        self.pending_next_key
            .as_ref()
            .map(|k| k.public_key())
            .ok_or(KelsError::NoNextKey)
    }

    async fn recovery_public_key(&self) -> Result<PublicKey, KelsError> {
        self.recovery_key
            .as_ref()
            .map(|k| k.public_key())
            .ok_or(KelsError::NoRecoveryKey)
    }

    async fn generate_into_current(&mut self) -> Result<PublicKey, KelsError> {
        let (public, private) = generate_secp256r1()?;
        self.current_key = Some(private);
        Ok(public)
    }

    async fn generate_into_next(&mut self) -> Result<PublicKey, KelsError> {
        let (public, private) = generate_secp256r1()?;
        self.next_key = Some(private);
        Ok(public)
    }

    async fn generate_recovery_key(&mut self) -> Result<PublicKey, KelsError> {
        let (public, private) = generate_secp256r1()?;
        self.recovery_key = Some(private);
        Ok(public)
    }

    async fn has_current(&self) -> bool {
        self.current_key.is_some()
    }

    async fn has_next(&self) -> bool {
        self.next_key.is_some()
    }

    async fn has_recovery(&self) -> bool {
        self.recovery_key.is_some()
    }

    async fn commit_recovery_rotation(&mut self) {
        if let Some(pending) = self.pending_recovery_key.take() {
            self.recovery_key = Some(pending);
        }
    }

    async fn commit_rotation(&mut self) {
        if let Some(pending_next) = self.pending_next_key.take() {
            self.current_key = self.next_key.take();
            self.next_key = Some(pending_next);
        }
    }

    async fn prepare_recovery_rotation(&mut self) -> Result<(PublicKey, PublicKey), KelsError> {
        let current_recovery = self
            .recovery_key
            .as_ref()
            .ok_or(KelsError::NoRecoveryKey)?
            .public_key();

        let (new_recovery_pub, new_recovery_priv) = generate_secp256r1()?;
        self.pending_recovery_key = Some(new_recovery_priv);

        Ok((current_recovery, new_recovery_pub))
    }

    async fn prepare_rotation(&mut self) -> Result<PublicKey, KelsError> {
        let new_current_pub = self
            .next_key
            .as_ref()
            .ok_or(KelsError::NoNextKey)?
            .public_key();

        let (_new_next_pub, new_next_priv) = generate_secp256r1()?;
        self.pending_next_key = Some(new_next_priv);

        Ok(new_current_pub)
    }

    async fn rollback_recovery_rotation(&mut self) {
        self.pending_recovery_key = None;
    }

    async fn rollback_rotation(&mut self) {
        self.pending_next_key = None;
    }

    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let key = self.current_key.as_ref().ok_or(KelsError::NoCurrentKey)?;
        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }

    async fn sign_with_pending(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let key = self.next_key.as_ref().ok_or(KelsError::NoCurrentKey)?;
        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }

    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        let key = self.recovery_key.as_ref().ok_or(KelsError::NoRecoveryKey)?;
        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }

    async fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError> {
        let public_key = self.current_public_key().await?;
        public_key
            .verify(data, signature)
            .map_err(|e| KelsError::VerificationFailed(e.to_string()))
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::Matter;

    #[tokio::test]
    async fn test_generate_keypair() {
        let mut provider = SoftwareKeyProvider::new();

        let current = provider.generate_keypair().await.unwrap();
        assert!(provider.current_public_key().await.is_ok());
        assert!(provider.next_public_key().await.is_err());

        let next = provider.generate_keypair().await.unwrap();
        assert!(provider.next_public_key().await.is_ok());

        assert_ne!(current.qb64(), next.qb64());
    }

    #[tokio::test]
    async fn test_rotation() {
        let mut provider = SoftwareKeyProvider::new();

        let _current = provider.generate_keypair().await.unwrap();
        let original_next = provider.generate_keypair().await.unwrap();

        let new_current = provider.prepare_rotation().await.unwrap();
        assert_eq!(new_current.qb64(), original_next.qb64());
        provider.commit_rotation().await;

        assert!(provider.next_public_key().await.is_ok());
    }

    #[tokio::test]
    async fn test_rotation_without_next_fails() {
        let mut provider = SoftwareKeyProvider::new();
        provider.generate_keypair().await.unwrap();
        assert!(provider.prepare_rotation().await.is_err());
    }

    #[tokio::test]
    async fn test_sign_without_key_fails() {
        let provider = SoftwareKeyProvider::new();
        assert!(provider.sign(b"test").await.is_err());
    }

    #[tokio::test]
    async fn test_recovery_key() {
        let mut provider = SoftwareKeyProvider::new();

        assert!(provider.recovery_public_key().await.is_err());

        let recovery = provider.generate_recovery_key().await.unwrap();
        assert!(provider.recovery_public_key().await.is_ok());
        assert_eq!(
            provider.recovery_public_key().await.unwrap().qb64(),
            recovery.qb64()
        );

        let message = b"test message";
        let sig = provider.sign_with_recovery(message).await.unwrap();
        assert!(recovery.verify(message, &sig).is_ok());
    }

    #[tokio::test]
    async fn test_recovery_rotation() {
        let mut provider = SoftwareKeyProvider::new();

        let original_recovery = provider.generate_recovery_key().await.unwrap();

        let (current_recovery, new_recovery) = provider.prepare_recovery_rotation().await.unwrap();
        assert_eq!(current_recovery.qb64(), original_recovery.qb64());
        assert_ne!(new_recovery.qb64(), original_recovery.qb64());

        assert_eq!(
            provider.recovery_public_key().await.unwrap().qb64(),
            original_recovery.qb64()
        );

        provider.commit_recovery_rotation().await;

        assert_eq!(
            provider.recovery_public_key().await.unwrap().qb64(),
            new_recovery.qb64()
        );
    }

    #[tokio::test]
    async fn test_sign() {
        let mut provider = SoftwareKeyProvider::new();
        provider.generate_into_current().await.unwrap();

        let message = b"test message";
        let signature = provider.sign(message).await.unwrap();

        let public = provider.current_public_key().await.unwrap();
        assert!(public.verify(message, &signature).is_ok());
    }

    #[tokio::test]
    async fn test_with_keys() {
        let (pub1, priv1) = generate_secp256r1().unwrap();
        let (pub2, priv2) = generate_secp256r1().unwrap();

        let provider = SoftwareKeyProvider::with_keys(priv1, priv2);

        assert_eq!(
            provider.current_public_key().await.unwrap().qb64(),
            pub1.qb64()
        );
        assert_eq!(
            provider.next_public_key().await.unwrap().qb64(),
            pub2.qb64()
        );
    }
}
