//! Cryptographic Key Provider

use crate::{compute_rotation_hash, error::KelsError};
use cesr::{Matter, PrivateKey, PublicKey, Signature, generate_secp256r1};
use std::path::{Path, PathBuf};

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
use crate::hardware::HardwareKeyProvider;

// ==================== ProviderConfig Trait ====================

/// Trait for provider configuration that handles creation and persistence.
#[async_trait::async_trait]
pub trait ProviderConfig: Send + Sync {
    /// The provider type this config creates.
    type Provider: KeyProvider;

    /// Loads or creates a provider from this configuration.
    async fn load_provider(&self) -> Result<Self::Provider, KelsError>;

    /// Saves the provider state.
    async fn save_provider(&self, provider: &Self::Provider) -> Result<(), KelsError>;
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

#[async_trait::async_trait]
impl ProviderConfig for SoftwareProviderConfig {
    type Provider = SoftwareKeyProvider;

    async fn load_provider(&self) -> Result<Self::Provider, KelsError> {
        if self.key_dir.exists() {
            SoftwareKeyProvider::load_from_dir(&self.key_dir)
        } else {
            Ok(SoftwareKeyProvider::new())
        }
    }

    async fn save_provider(&self, provider: &Self::Provider) -> Result<(), KelsError> {
        provider.save_to_dir(&self.key_dir).await
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
#[async_trait::async_trait]
impl ProviderConfig for HardwareProviderConfig {
    type Provider = HardwareKeyProvider;

    async fn load_provider(&self) -> Result<Self::Provider, KelsError> {
        HardwareKeyProvider::new(&self.namespace)
            .ok_or_else(|| KelsError::HardwareError("Secure Enclave not available".into()))
    }

    async fn save_provider(&self, _provider: &Self::Provider) -> Result<(), KelsError> {
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
/// 1. `stage_rotation()` - stages the rotation (next becomes pending current, new next generated)
/// 2. `commit()` or `rollback()` - finalizes or reverts
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    // ==================== Accessors ====================

    /// Returns the signing key generation counter (for persistence).
    async fn signing_generation(&self) -> u64 {
        0
    }

    /// Returns the recovery key generation counter (for persistence).
    async fn recovery_generation(&self) -> u64 {
        0
    }

    /// Returns the handle/label for the current key (for persistence).
    async fn current_handle(&self) -> Option<String> {
        None
    }

    /// Returns the handle/label for the next key (for persistence).
    async fn next_handle(&self) -> Option<String> {
        None
    }

    /// Returns the handle/label for the recovery key (for persistence).
    async fn recovery_handle(&self) -> Option<String> {
        None
    }

    /// Returns the current signing public key.
    async fn current_public_key(&self) -> Result<PublicKey, KelsError>;

    // ==================== Key Generation ====================

    async fn generate_initial_keys(&mut self) -> Result<(PublicKey, String, String), KelsError>;

    // ==================== Query Methods ====================

    /// Returns true if a current key exists.
    async fn has_current(&self) -> bool;

    /// Returns true if a next key exists.
    async fn has_next(&self) -> bool;

    async fn has_staged(&self) -> bool;

    /// Returns true if a recovery key exists.
    async fn has_recovery(&self) -> bool;

    async fn has_staged_recovery(&self) -> bool;

    // ==================== Rotation Operations ====================

    /// Prepares a key rotation. Returns the new current public key (what next will become).
    async fn stage_rotation(&mut self) -> Result<(PublicKey, String), KelsError>;

    /// Prepares a recovery key rotation. Returns (current_recovery_pub, new_recovery_pub).
    async fn stage_recovery_rotation(&mut self) -> Result<(PublicKey, String), KelsError>;

    /// Commits a staged key rotation (pending becomes active).
    async fn commit(&mut self) -> Result<(), KelsError>;

    /// Reverts a staged key rotation.
    async fn rollback(&mut self) -> Result<(), KelsError>;

    // ==================== Signing ====================

    /// Signs data with the current key.
    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError>;

    /// Signs data with the recovery key.
    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError>;

    // ==================== Convenience Methods ====================
}

// ==================== SoftwareKeyProvider ====================

#[derive(Debug, Clone)]
pub struct SoftwareKeyProvider {
    keys: Vec<PrivateKey>,
    recovery_keys: Vec<PrivateKey>,
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
            keys: Vec::new(),
            recovery_keys: Vec::new(),
        }
    }

    pub fn with_all_keys(
        current: Option<PrivateKey>,
        next: Option<PrivateKey>,
        recovery: Option<PrivateKey>,
    ) -> Self {
        if let Some(c) = current
            && let Some(n) = next
            && let Some(r) = recovery
        {
            return Self {
                keys: vec![c, n],
                recovery_keys: vec![r],
            };
        }

        Self::new()
    }

    // ==================== Persistence ====================

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
    pub async fn save_to_dir(&self, dir: &Path) -> Result<(), KelsError> {
        if !self.has_current().await {
            return Err(KelsError::NoCurrentKey);
        }

        if !self.has_next().await {
            return Err(KelsError::NoNextKey);
        }

        if !self.has_recovery().await {
            return Err(KelsError::NoRecoveryKey);
        }

        if self.has_staged().await || self.has_staged_recovery().await {
            return Err(KelsError::CurrentlyStaged);
        }

        std::fs::create_dir_all(dir).map_err(|e| {
            KelsError::HardwareError(format!("Failed to create key directory: {}", e))
        })?;

        if let Some(key) = self.keys.first() {
            let path = dir.join("current.key");
            std::fs::write(&path, key.qb64()).map_err(|e| {
                KelsError::HardwareError(format!("Failed to write current key: {}", e))
            })?;
        } else {
            return Err(KelsError::NoCurrentKey);
        }
        if let Some(key) = &self.keys.last() {
            let path = dir.join("next.key");
            std::fs::write(&path, key.qb64()).map_err(|e| {
                KelsError::HardwareError(format!("Failed to write next key: {}", e))
            })?;
        } else {
            return Err(KelsError::NoNextKey);
        }

        if let Some(key) = &self.recovery_keys.first() {
            let path = dir.join("recovery.key");
            std::fs::write(&path, key.qb64()).map_err(|e| {
                KelsError::HardwareError(format!("Failed to write recovery key: {}", e))
            })?;
        } else {
            return Err(KelsError::NoRecoveryKey);
        }

        Ok(())
    }
}

// Test-only private key accessors
#[cfg(test)]
impl SoftwareKeyProvider {
    pub fn current_private_key(&self) -> Option<&PrivateKey> {
        self.keys.first()
    }

    pub fn next_private_key(&self) -> Option<&PrivateKey> {
        self.keys.last()
    }

    pub fn recovery_private_key(&self) -> Option<&PrivateKey> {
        self.recovery_keys.first()
    }
}

// ==================== KeyProvider impl for SoftwareKeyProvider ====================

#[async_trait::async_trait]
impl KeyProvider for SoftwareKeyProvider {
    async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoCurrentKey);
        }

        let index = self.keys.len() - 2;
        Ok(self.keys[index].public_key())
    }

    async fn generate_initial_keys(&mut self) -> Result<(PublicKey, String, String), KelsError> {
        let (public, private) = generate_secp256r1()?;
        let (next_public, next_private) = generate_secp256r1()?;
        let (recovery_public, recovery_private) = generate_secp256r1()?;

        let rotation_hash = compute_rotation_hash(&next_public.qb64());
        let recovery_hash = compute_rotation_hash(&recovery_public.qb64());

        self.keys = vec![private, next_private];
        self.recovery_keys = vec![recovery_private];

        Ok((public, rotation_hash, recovery_hash))
    }

    async fn has_current(&self) -> bool {
        !self.keys.is_empty()
    }

    async fn has_next(&self) -> bool {
        self.keys.len() > 1
    }

    async fn has_staged(&self) -> bool {
        self.keys.len() > 2
    }

    async fn has_recovery(&self) -> bool {
        !self.recovery_keys.is_empty()
    }

    async fn has_staged_recovery(&self) -> bool {
        self.recovery_keys.len() > 1
    }

    async fn stage_rotation(&mut self) -> Result<(PublicKey, String), KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoNextKey);
        }

        let new_current_pub = {
            let length = self.keys.len();
            self.keys[length - 1].public_key()
        };

        let (new_next_pub, new_next_priv) = generate_secp256r1()?;
        self.keys.push(new_next_priv);

        let rotation_hash = compute_rotation_hash(&new_next_pub.qb64());

        Ok((new_current_pub, rotation_hash))
    }

    async fn stage_recovery_rotation(&mut self) -> Result<(PublicKey, String), KelsError> {
        if !self.has_recovery().await {
            return Err(KelsError::NoRecoveryKey);
        }

        let current_recovery = self.recovery_keys[0].public_key();

        let (new_recovery_pub, new_recovery_priv) = generate_secp256r1()?;
        self.recovery_keys.push(new_recovery_priv);
        let new_recovery_hash = compute_rotation_hash(&new_recovery_pub.qb64());

        Ok((current_recovery, new_recovery_hash))
    }

    async fn commit(&mut self) -> Result<(), KelsError> {
        if !self.has_staged().await {
            return Err(KelsError::NoStagedKey);
        }

        if self.has_staged_recovery().await {
            let length = self.recovery_keys.len();
            self.recovery_keys = self.recovery_keys[(length - 1)..].to_vec();
        }

        let length = self.keys.len();
        self.keys = self.keys[(length - 2)..].to_vec();

        Ok(())
    }

    async fn rollback(&mut self) -> Result<(), KelsError> {
        if !self.has_staged().await {
            return Err(KelsError::NoStagedKey);
        }

        if self.has_staged_recovery().await {
            self.recovery_keys = self.recovery_keys[..1].to_vec();
        }

        self.keys = self.keys[..2].to_vec();

        Ok(())
    }

    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        // this is correct, the error makes sense to the user
        if !self.has_next().await {
            return Err(KelsError::NoCurrentKey);
        }

        let length = self.keys.len();
        let key = &self.keys[length - 2];

        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }

    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        if !self.has_recovery().await {
            return Err(KelsError::NoRecoveryKey);
        }

        let key = &self.recovery_keys[0];

        key.sign(data)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::Matter;

    #[tokio::test]
    async fn test_generate_initial_keys() {
        let mut provider = SoftwareKeyProvider::new();

        let (current, next_hash, recovery_hash) = provider.generate_initial_keys().await.unwrap();
        assert!(provider.current_public_key().await.is_ok());
        assert_eq!(
            provider.current_public_key().await.unwrap().qb64(),
            current.qb64()
        );

        assert_ne!(next_hash, recovery_hash);
        assert!(provider.has_current().await);
        assert!(provider.has_next().await);
        assert!(provider.has_recovery().await);
    }

    #[tokio::test]
    async fn test_rotation() {
        let mut provider = SoftwareKeyProvider::new();

        let (_current, _next_hash, _recovery_hash) =
            provider.generate_initial_keys().await.unwrap();

        // Stage rotation: next becomes new current, new next is generated
        let (new_current, _new_next_hash) = provider.stage_rotation().await.unwrap();
        assert!(provider.has_staged().await);

        provider.commit().await.unwrap();
        assert!(!provider.has_staged().await);

        // After commit, new_current is now current
        assert_eq!(
            provider.current_public_key().await.unwrap().qb64(),
            new_current.qb64()
        );
    }

    #[tokio::test]
    async fn test_rotation_without_next_fails() {
        let mut provider = SoftwareKeyProvider::new();
        // No keys at all - should fail
        assert!(provider.stage_rotation().await.is_err());
    }

    #[tokio::test]
    async fn test_sign_without_key_fails() {
        let provider = SoftwareKeyProvider::new();
        assert!(provider.sign(b"test").await.is_err());
    }

    #[tokio::test]
    async fn test_recovery_rotation() {
        let mut provider = SoftwareKeyProvider::new();

        let (_current, _next_hash, _recovery_hash) =
            provider.generate_initial_keys().await.unwrap();

        // Stage recovery rotation
        let (_, _) = provider.stage_rotation().await.unwrap();
        let (_current_recovery, _new_recovery_hash) =
            provider.stage_recovery_rotation().await.unwrap();
        assert!(provider.has_staged_recovery().await);
        assert!(provider.has_staged().await);

        provider.commit().await.unwrap();
        assert!(!provider.has_staged_recovery().await);
        assert!(!provider.has_staged().await);

        // The old recovery key is gone, we can't easily verify the new one without
        // exposing the recovery public key, but we can sign with recovery
        let message = b"test message";
        let sig = provider.sign_with_recovery(message).await.unwrap();
        // Can't verify directly without recovery_public_key, but sign succeeded
        assert!(!sig.qb64().is_empty());
    }

    #[tokio::test]
    async fn test_sign() {
        let mut provider = SoftwareKeyProvider::new();
        let (current, _next_hash, _recovery_hash) = provider.generate_initial_keys().await.unwrap();

        let message = b"test message";
        let signature = provider.sign(message).await.unwrap();

        assert!(current.verify(message, &signature).is_ok());
    }

    #[tokio::test]
    async fn test_with_all_keys() {
        let (pub1, priv1) = generate_secp256r1().unwrap();
        let (_pub2, priv2) = generate_secp256r1().unwrap();
        let (_pub3, priv3) = generate_secp256r1().unwrap();

        let provider = SoftwareKeyProvider::with_all_keys(Some(priv1), Some(priv2), Some(priv3));

        assert_eq!(
            provider.current_public_key().await.unwrap().qb64(),
            pub1.qb64()
        );
        // We can sign and the signature should be verifiable with pub1
        let message = b"test";
        let sig = provider.sign(message).await.unwrap();
        assert!(pub1.verify(message, &sig).is_ok());
    }

    #[tokio::test]
    async fn test_rollback_rotation() {
        let mut provider = SoftwareKeyProvider::new();

        let (original_current, _next_hash, _recovery_hash) =
            provider.generate_initial_keys().await.unwrap();

        // Stage a rotation
        let (_new_current, _new_next_hash) = provider.stage_rotation().await.unwrap();
        assert!(provider.has_staged().await);

        // Rollback
        provider.rollback().await.unwrap();
        assert!(!provider.has_staged().await);

        // Current should still be the original
        assert_eq!(
            provider.current_public_key().await.unwrap().qb64(),
            original_current.qb64()
        );
    }

    #[tokio::test]
    async fn test_rollback_recovery_rotation() {
        let mut provider = SoftwareKeyProvider::new();

        let (_current, _next_hash, _recovery_hash) =
            provider.generate_initial_keys().await.unwrap();

        // Stage a recovery rotation
        let (_, _) = provider.stage_rotation().await.unwrap();
        let (_old_recovery, _new_recovery_hash) = provider.stage_recovery_rotation().await.unwrap();
        assert!(provider.has_staged_recovery().await);
        assert!(provider.has_staged().await);

        // Rollback
        provider.rollback().await.unwrap();
        assert!(!provider.has_staged_recovery().await);
        assert!(!provider.has_staged().await);
    }
}
