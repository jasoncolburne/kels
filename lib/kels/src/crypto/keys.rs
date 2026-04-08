//! Cryptographic key provider — key generation, rotation, signing, and persistence.

use std::path::{Path, PathBuf};

use cesr::{
    Signature, SigningKey, VerificationKey, VerificationKeyCode, generate_ml_dsa_65,
    generate_ml_dsa_87, generate_secp256r1,
};
use serde::{Deserialize, Serialize};

use crate::{compute_rotation_hash, error::KelsError};

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
    pub signing_algorithm: VerificationKeyCode,
    pub recovery_algorithm: VerificationKeyCode,
}

impl SoftwareProviderConfig {
    pub fn new(
        key_dir: PathBuf,
        signing_algorithm: VerificationKeyCode,
        recovery_algorithm: VerificationKeyCode,
    ) -> Self {
        Self {
            key_dir,
            signing_algorithm,
            recovery_algorithm,
        }
    }
}

#[async_trait::async_trait]
impl ProviderConfig for SoftwareProviderConfig {
    type Provider = SoftwareKeyProvider;

    async fn load_provider(&self) -> Result<Self::Provider, KelsError> {
        if self.key_dir.exists() {
            SoftwareKeyProvider::load_from_dir(&self.key_dir)
        } else {
            Ok(SoftwareKeyProvider::new(
                self.signing_algorithm,
                self.recovery_algorithm,
            ))
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
    pub signing_algorithm: VerificationKeyCode,
    pub recovery_algorithm: VerificationKeyCode,
}

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
impl HardwareProviderConfig {
    pub fn new(
        namespace: String,
        signing_algorithm: VerificationKeyCode,
        recovery_algorithm: VerificationKeyCode,
    ) -> Self {
        Self {
            namespace,
            signing_algorithm,
            recovery_algorithm,
        }
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
        HardwareKeyProvider::new(
            &self.namespace,
            self.signing_algorithm,
            self.recovery_algorithm,
        )
        .ok_or_else(|| KelsError::HardwareError("Secure Enclave not available".into()))
    }

    async fn save_provider(&self, _provider: &Self::Provider) -> Result<(), KelsError> {
        // Hardware keys persist automatically in the Secure Enclave
        Ok(())
    }
}

// ==================== KeyStateStore Trait ====================

/// Opaque key state storage backend.
///
/// Implementors choose where to persist key state (filesystem, Keychain, CoreData, etc.).
/// The provider decides the encoding — the store just handles opaque bytes.
pub trait KeyStateStore: Send + Sync {
    fn save(&self, key: &str, data: &[u8]) -> Result<(), KelsError>;
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, KelsError>;
    fn delete(&self, key: &str) -> Result<(), KelsError>;
}

/// Write a file and restrict its permissions to owner-only (0o600 on Unix).
fn write_key_file(path: &Path, data: &str) -> Result<(), KelsError> {
    std::fs::write(path, data)
        .map_err(|e| KelsError::HardwareError(format!("Failed to write key file: {}", e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            KelsError::HardwareError(format!("Failed to set key file permissions: {}", e))
        })?;
    }
    Ok(())
}

/// Ensure a directory exists with owner-only permissions (0o700 on Unix).
fn ensure_private_dir(dir: &Path) -> Result<(), KelsError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| KelsError::StorageError(format!("Failed to create dir: {}", e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            KelsError::StorageError(format!("Failed to set dir permissions: {}", e))
        })?;
    }
    Ok(())
}

/// File-based key state storage.
pub struct FileKeyStateStore {
    dir: PathBuf,
}

impl FileKeyStateStore {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }
}

impl KeyStateStore for FileKeyStateStore {
    fn save(&self, key: &str, data: &[u8]) -> Result<(), KelsError> {
        ensure_private_dir(&self.dir)?;
        let path = self.dir.join(format!("{}.keys.json", key));
        std::fs::write(&path, data)
            .map_err(|e| KelsError::StorageError(format!("Failed to write key state: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| KelsError::StorageError(format!("Failed to set key state permissions: {}", e)),
            )?;
        }
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, KelsError> {
        let path = self.dir.join(format!("{}.keys.json", key));
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KelsError::StorageError(format!(
                "Failed to read key state: {}",
                e
            ))),
        }
    }

    fn delete(&self, key: &str) -> Result<(), KelsError> {
        let path = self.dir.join(format!("{}.keys.json", key));
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KelsError::StorageError(format!(
                "Failed to delete key state: {}",
                e
            ))),
        }
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
    async fn current_public_key(&self) -> Result<VerificationKey, KelsError>;

    // ==================== Key Generation ====================

    async fn generate_initial_keys(
        &mut self,
    ) -> Result<(VerificationKey, cesr::Digest, cesr::Digest), KelsError>;

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
    async fn stage_rotation(&mut self) -> Result<(VerificationKey, cesr::Digest), KelsError>;

    /// Prepares a recovery key rotation. Returns (current_recovery_pub, new_recovery_pub).
    async fn stage_recovery_rotation(
        &mut self,
    ) -> Result<(VerificationKey, cesr::Digest), KelsError>;

    /// Commits a staged key rotation (pending becomes active).
    async fn commit(&mut self) -> Result<(), KelsError>;

    /// Reverts a staged key rotation.
    async fn rollback(&mut self) -> Result<(), KelsError>;

    // ==================== Signing ====================

    /// Signs data with the current key.
    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError>;

    /// Signs data with the recovery key.
    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError>;

    // ==================== Algorithm Configuration ====================

    /// Set the signing algorithm for future key generation.
    /// Default implementation returns an error (e.g., hardware providers don't support this).
    async fn set_signing_algorithm(
        &mut self,
        _algorithm: VerificationKeyCode,
    ) -> Result<(), KelsError> {
        Err(KelsError::HardwareError(
            "Algorithm change not supported by this provider".into(),
        ))
    }

    /// Set the recovery algorithm for future key generation.
    /// Default implementation returns an error (e.g., hardware providers don't support this).
    async fn set_recovery_algorithm(
        &mut self,
        _algorithm: VerificationKeyCode,
    ) -> Result<(), KelsError> {
        Err(KelsError::HardwareError(
            "Algorithm change not supported by this provider".into(),
        ))
    }

    // ==================== State Persistence ====================

    /// Save provider state to an opaque store. Each provider encodes its own format.
    async fn save_state(&self, store: &dyn KeyStateStore, prefix: &cesr::Digest) -> Result<(), KelsError>;

    /// Restore provider state from an opaque store. Returns true if state was found.
    async fn restore_state(
        &mut self,
        store: &dyn KeyStateStore,
        prefix: &cesr::Digest,
    ) -> Result<bool, KelsError>;
}

fn generate_for_algorithm(
    algorithm: VerificationKeyCode,
) -> Result<(VerificationKey, SigningKey), KelsError> {
    match algorithm {
        VerificationKeyCode::Secp256r1 => {
            generate_secp256r1().map_err(|e| KelsError::KeyGenerationFailed(e.to_string()))
        }
        VerificationKeyCode::MlDsa65 => {
            generate_ml_dsa_65().map_err(|e| KelsError::KeyGenerationFailed(e.to_string()))
        }
        VerificationKeyCode::MlDsa87 => {
            generate_ml_dsa_87().map_err(|e| KelsError::KeyGenerationFailed(e.to_string()))
        }
    }
}

// ==================== SoftwareKeyProvider ====================

#[derive(Debug, Clone)]
pub struct SoftwareKeyProvider {
    signing_algorithm: VerificationKeyCode,
    recovery_algorithm: VerificationKeyCode,
    keys: Vec<SigningKey>,
    recovery_keys: Vec<SigningKey>,
}

impl Default for SoftwareKeyProvider {
    fn default() -> Self {
        Self::new(VerificationKeyCode::MlDsa65, VerificationKeyCode::MlDsa65)
    }
}

impl SoftwareKeyProvider {
    // ==================== Constructors ====================

    pub fn new(
        signing_algorithm: VerificationKeyCode,
        recovery_algorithm: VerificationKeyCode,
    ) -> Self {
        Self {
            signing_algorithm,
            recovery_algorithm,
            keys: Vec::new(),
            recovery_keys: Vec::new(),
        }
    }

    pub fn with_all_keys(current: SigningKey, next: SigningKey, recovery: SigningKey) -> Self {
        // Infer signing algorithm from next key (what future rotations will use)
        let signing_algorithm = next.algorithm();
        let recovery_algorithm = recovery.algorithm();
        Self {
            signing_algorithm,
            recovery_algorithm,
            keys: vec![current, next],
            recovery_keys: vec![recovery],
        }
    }

    // ==================== Key Generation ====================

    fn generate_signing_keypair(&self) -> Result<(VerificationKey, SigningKey), KelsError> {
        generate_for_algorithm(self.signing_algorithm)
    }

    fn generate_recovery_keypair(&self) -> Result<(VerificationKey, SigningKey), KelsError> {
        generate_for_algorithm(self.recovery_algorithm)
    }

    // ==================== Persistence ====================

    /// Loads keys from a directory containing key files.
    /// Algorithm is auto-detected from CESR code prefix.
    pub fn load_from_dir(dir: &Path) -> Result<Self, KelsError> {
        let current_path = dir.join("current.key");
        let next_path = dir.join("next.key");
        let recovery_path = dir.join("recovery.key");

        if !current_path.exists() {
            return Err(KelsError::NoCurrentKey);
        }
        if !next_path.exists() {
            return Err(KelsError::NoNextKey);
        }
        if !recovery_path.exists() {
            return Err(KelsError::NoRecoveryKey);
        }

        let current_qb64 = std::fs::read_to_string(&current_path)
            .map_err(|e| KelsError::HardwareError(format!("Failed to read current key: {}", e)))?;
        let current = SigningKey::from_qb64(current_qb64.trim())?;

        let next_qb64 = std::fs::read_to_string(&next_path)
            .map_err(|e| KelsError::HardwareError(format!("Failed to read next key: {}", e)))?;
        let next = SigningKey::from_qb64(next_qb64.trim())?;

        let recovery_qb64 = std::fs::read_to_string(&recovery_path)
            .map_err(|e| KelsError::HardwareError(format!("Failed to read recovery key: {}", e)))?;
        let recovery = SigningKey::from_qb64(recovery_qb64.trim())?;

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

        ensure_private_dir(dir)?;

        if let Some(key) = self.keys.first() {
            let path = dir.join("current.key");
            write_key_file(&path, &key.qb64())?;
        } else {
            return Err(KelsError::NoCurrentKey);
        }
        if let Some(key) = &self.keys.last() {
            let path = dir.join("next.key");
            write_key_file(&path, &key.qb64())?;
        } else {
            return Err(KelsError::NoNextKey);
        }

        if let Some(key) = &self.recovery_keys.first() {
            let path = dir.join("recovery.key");
            write_key_file(&path, &key.qb64())?;
        } else {
            return Err(KelsError::NoRecoveryKey);
        }

        Ok(())
    }
}

// Test-only private key accessors
#[cfg(test)]
impl SoftwareKeyProvider {
    pub fn current_private_key(&self) -> Option<&SigningKey> {
        self.keys.first()
    }

    pub fn next_private_key(&self) -> Option<&SigningKey> {
        self.keys.last()
    }

    pub fn recovery_private_key(&self) -> Option<&SigningKey> {
        self.recovery_keys.first()
    }
}

// ==================== KeyProvider impl for SoftwareKeyProvider ====================

#[async_trait::async_trait]
impl KeyProvider for SoftwareKeyProvider {
    async fn current_public_key(&self) -> Result<VerificationKey, KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoCurrentKey);
        }

        let index = self.keys.len() - 2;
        Ok(self.keys[index].verification_key())
    }

    async fn generate_initial_keys(
        &mut self,
    ) -> Result<(VerificationKey, cesr::Digest, cesr::Digest), KelsError> {
        let (public, private) = self.generate_signing_keypair()?;
        let (next_public, next_private) = self.generate_signing_keypair()?;
        let (recovery_public, recovery_private) = self.generate_recovery_keypair()?;

        let rotation_hash = compute_rotation_hash(&next_public);
        let recovery_hash = compute_rotation_hash(&recovery_public);

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

    async fn stage_rotation(&mut self) -> Result<(VerificationKey, cesr::Digest), KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoNextKey);
        }

        let new_current_pub = {
            let length = self.keys.len();
            self.keys[length - 1].verification_key()
        };

        let (new_next_pub, new_next_priv) = self.generate_signing_keypair()?;
        self.keys.push(new_next_priv);

        let rotation_hash = compute_rotation_hash(&new_next_pub);

        Ok((new_current_pub, rotation_hash))
    }

    async fn stage_recovery_rotation(
        &mut self,
    ) -> Result<(VerificationKey, cesr::Digest), KelsError> {
        if !self.has_recovery().await {
            return Err(KelsError::NoRecoveryKey);
        }

        let current_recovery = self.recovery_keys[0].verification_key();

        let (new_recovery_pub, new_recovery_priv) = self.generate_recovery_keypair()?;
        self.recovery_keys.push(new_recovery_priv);
        let new_recovery_hash = compute_rotation_hash(&new_recovery_pub);

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

    async fn set_signing_algorithm(
        &mut self,
        algorithm: VerificationKeyCode,
    ) -> Result<(), KelsError> {
        self.signing_algorithm = algorithm;
        Ok(())
    }

    async fn set_recovery_algorithm(
        &mut self,
        algorithm: VerificationKeyCode,
    ) -> Result<(), KelsError> {
        self.recovery_algorithm = algorithm;
        Ok(())
    }

    async fn save_state(&self, store: &dyn KeyStateStore, prefix: &cesr::Digest) -> Result<(), KelsError> {
        let state = SoftwareKeyState {
            signing_algorithm: Some(self.signing_algorithm),
            recovery_algorithm: Some(self.recovery_algorithm),
            keys: self.keys.iter().map(|k| k.qb64()).collect(),
            recovery_keys: self.recovery_keys.iter().map(|k| k.qb64()).collect(),
        };
        let data =
            serde_json::to_vec(&state).map_err(|e| KelsError::StorageError(e.to_string()))?;
        store.save(prefix.as_ref(), &data)
    }

    async fn restore_state(
        &mut self,
        store: &dyn KeyStateStore,
        prefix: &cesr::Digest,
    ) -> Result<bool, KelsError> {
        let Some(data) = store.load(prefix.as_ref())? else {
            return Ok(false);
        };

        let state: SoftwareKeyState =
            serde_json::from_slice(&data).map_err(|e| KelsError::StorageError(e.to_string()))?;

        let keys: Vec<SigningKey> = state
            .keys
            .iter()
            .map(|qb64| SigningKey::from_qb64(qb64))
            .collect::<Result<Vec<_>, _>>()?;
        let recovery_keys: Vec<SigningKey> = state
            .recovery_keys
            .iter()
            .map(|qb64| SigningKey::from_qb64(qb64))
            .collect::<Result<Vec<_>, _>>()?;

        if keys.len() < 2 {
            return Err(KelsError::StorageError(format!(
                "Corrupted key state: expected at least 2 signing keys, found {}",
                keys.len()
            )));
        }
        if recovery_keys.is_empty() {
            return Err(KelsError::StorageError(
                "Corrupted key state: no recovery key".to_string(),
            ));
        }

        if let Some(algo) = state.signing_algorithm {
            self.signing_algorithm = algo;
        }
        if let Some(algo) = state.recovery_algorithm {
            self.recovery_algorithm = algo;
        }

        self.keys = keys;
        self.recovery_keys = recovery_keys;

        Ok(true)
    }
}

#[derive(Serialize, Deserialize)]
struct SoftwareKeyState {
    #[serde(default)]
    signing_algorithm: Option<VerificationKeyCode>,
    #[serde(default)]
    recovery_algorithm: Option<VerificationKeyCode>,
    keys: Vec<String>,
    recovery_keys: Vec<String>,
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::Matter;

    fn random_provider() -> SoftwareKeyProvider {
        use rand::Rng;
        let mut rng = rand::rng();
        let algorithms = [
            VerificationKeyCode::Secp256r1,
            VerificationKeyCode::MlDsa65,
            VerificationKeyCode::MlDsa87,
        ];
        let signing_idx = rng.random_range(0..algorithms.len());
        let recovery_idx = rng.random_range(signing_idx..algorithms.len());
        SoftwareKeyProvider::new(algorithms[signing_idx], algorithms[recovery_idx])
    }

    #[tokio::test]
    async fn test_generate_initial_keys() {
        let mut provider = random_provider();

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
    async fn test_generate_initial_keys_ml_dsa_65() {
        let mut provider =
            SoftwareKeyProvider::new(VerificationKeyCode::MlDsa65, VerificationKeyCode::MlDsa65);

        let (current, next_hash, recovery_hash) = provider.generate_initial_keys().await.unwrap();
        assert_eq!(current.algorithm(), VerificationKeyCode::MlDsa65);
        assert!(provider.current_public_key().await.is_ok());
        assert_eq!(
            provider.current_public_key().await.unwrap().qb64(),
            current.qb64()
        );

        assert_ne!(next_hash, recovery_hash);
    }

    #[tokio::test]
    async fn test_rotation() {
        let mut provider = random_provider();

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
        let mut provider = random_provider();
        // No keys at all - should fail
        assert!(provider.stage_rotation().await.is_err());
    }

    #[tokio::test]
    async fn test_sign_without_key_fails() {
        let provider = random_provider();
        assert!(provider.sign(b"test").await.is_err());
    }

    #[tokio::test]
    async fn test_recovery_rotation() {
        let mut provider = random_provider();

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
        let mut provider = random_provider();
        let (current, _next_hash, _recovery_hash) = provider.generate_initial_keys().await.unwrap();

        let message = b"test message";
        let signature = provider.sign(message).await.unwrap();

        assert!(current.verify(message, &signature).is_ok());
    }

    #[tokio::test]
    async fn test_sign_ml_dsa_65() {
        let mut provider =
            SoftwareKeyProvider::new(VerificationKeyCode::MlDsa65, VerificationKeyCode::MlDsa65);
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

        let provider = SoftwareKeyProvider::with_all_keys(priv1, priv2, priv3);

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
        let mut provider = random_provider();

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
        let mut provider = random_provider();

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

    #[test]
    fn test_software_key_provider_default() {
        let provider = SoftwareKeyProvider::default();
        assert!(provider.keys.is_empty());
        assert!(provider.recovery_keys.is_empty());
    }

    #[tokio::test]
    async fn test_sign_with_recovery_without_key_fails() {
        let provider = random_provider();
        let result = provider.sign_with_recovery(b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_stage_recovery_rotation_without_key_fails() {
        let mut provider = random_provider();
        let result = provider.stage_recovery_rotation().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_commit_without_staged_fails() {
        let mut provider = random_provider();
        provider.generate_initial_keys().await.unwrap();
        let result = provider.commit().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rollback_without_staged_fails() {
        let mut provider = random_provider();
        provider.generate_initial_keys().await.unwrap();
        let result = provider.rollback().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_current_public_key_without_next_fails() {
        let provider = random_provider();
        let result = provider.current_public_key().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_save_and_load_roundtrip() {
        use tempfile::TempDir;

        let mut provider = random_provider();
        provider.generate_initial_keys().await.unwrap();
        let original_pub = provider.current_public_key().await.unwrap();

        let temp = TempDir::new().unwrap();
        provider.save_to_dir(temp.path()).await.unwrap();

        let loaded = SoftwareKeyProvider::load_from_dir(temp.path()).unwrap();
        assert_eq!(
            loaded.current_public_key().await.unwrap().qb64(),
            original_pub.qb64()
        );
    }

    #[tokio::test]
    async fn test_save_and_load_roundtrip_ml_dsa_65() {
        use tempfile::TempDir;

        let mut provider =
            SoftwareKeyProvider::new(VerificationKeyCode::MlDsa65, VerificationKeyCode::MlDsa65);
        provider.generate_initial_keys().await.unwrap();
        let original_pub = provider.current_public_key().await.unwrap();
        assert_eq!(original_pub.algorithm(), VerificationKeyCode::MlDsa65);

        let temp = TempDir::new().unwrap();
        provider.save_to_dir(temp.path()).await.unwrap();

        let loaded = SoftwareKeyProvider::load_from_dir(temp.path()).unwrap();
        assert_eq!(
            loaded.current_public_key().await.unwrap().qb64(),
            original_pub.qb64()
        );
        assert_eq!(loaded.signing_algorithm, VerificationKeyCode::MlDsa65);
    }

    #[tokio::test]
    async fn test_save_without_current_fails() {
        use tempfile::TempDir;

        let provider = random_provider();
        let temp = TempDir::new().unwrap();
        let result = provider.save_to_dir(temp.path()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_save_while_staged_fails() {
        use tempfile::TempDir;

        let mut provider = random_provider();
        provider.generate_initial_keys().await.unwrap();
        provider.stage_rotation().await.unwrap();

        let temp = TempDir::new().unwrap();
        let result = provider.save_to_dir(temp.path()).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_nonexistent_dir() {
        let result = SoftwareKeyProvider::load_from_dir(Path::new("/nonexistent/path/12345"));
        // Should fail with NoCurrentKey if directory doesn't exist
        assert!(matches!(result, Err(KelsError::NoCurrentKey)));
    }

    #[test]
    fn test_software_provider_config_new() {
        let config = SoftwareProviderConfig::new(
            PathBuf::from("/tmp/keys"),
            VerificationKeyCode::Secp256r1,
            VerificationKeyCode::Secp256r1,
        );
        assert_eq!(config.key_dir, PathBuf::from("/tmp/keys"));
    }

    #[tokio::test]
    async fn test_software_provider_config_load_new() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let nonexistent = temp.path().join("nonexistent");
        let config = SoftwareProviderConfig::new(
            nonexistent,
            VerificationKeyCode::Secp256r1,
            VerificationKeyCode::Secp256r1,
        );

        let provider = config.load_provider().await.unwrap();
        assert!(!provider.has_current().await);
    }

    #[tokio::test]
    async fn test_software_provider_config_save_and_load() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let key_dir = temp.path().join("keys");
        let config = SoftwareProviderConfig::new(
            key_dir.clone(),
            VerificationKeyCode::Secp256r1,
            VerificationKeyCode::Secp256r1,
        );

        // Create and save a provider
        let mut provider = random_provider();
        provider.generate_initial_keys().await.unwrap();
        let original_pub = provider.current_public_key().await.unwrap();
        config.save_provider(&provider).await.unwrap();

        // Load it back
        let config2 = SoftwareProviderConfig::new(
            key_dir,
            VerificationKeyCode::Secp256r1,
            VerificationKeyCode::Secp256r1,
        );
        let loaded = config2.load_provider().await.unwrap();
        assert_eq!(
            loaded.current_public_key().await.unwrap().qb64(),
            original_pub.qb64()
        );
    }

    #[tokio::test]
    async fn test_mixed_algorithm_p256_signing_ml_dsa_recovery() {
        let mut provider =
            SoftwareKeyProvider::new(VerificationKeyCode::Secp256r1, VerificationKeyCode::MlDsa65);

        let (current, _next_hash, _recovery_hash) = provider.generate_initial_keys().await.unwrap();
        assert_eq!(current.algorithm(), VerificationKeyCode::Secp256r1);

        // Signing key is P-256
        let message = b"test message";
        let sig = provider.sign(message).await.unwrap();
        assert!(current.verify(message, &sig).is_ok());

        // Recovery key is ML-DSA-65
        let recovery_sig = provider.sign_with_recovery(message).await.unwrap();
        assert_eq!(recovery_sig.algorithm(), cesr::SignatureCode::MlDsa65);
    }

    #[tokio::test]
    async fn test_algorithm_upgrade_p256_to_ml_dsa() {
        // Start with P-256
        let mut provider = SoftwareKeyProvider::new(
            VerificationKeyCode::Secp256r1,
            VerificationKeyCode::Secp256r1,
        );
        let (current, _next_hash, _recovery_hash) = provider.generate_initial_keys().await.unwrap();
        assert_eq!(current.algorithm(), VerificationKeyCode::Secp256r1);

        // User decides to upgrade to ML-DSA-65
        provider.signing_algorithm = VerificationKeyCode::MlDsa65;

        // Stage rotation — next key will be ML-DSA-65
        let (new_current, _new_next_hash) = provider.stage_rotation().await.unwrap();
        // new_current is the old P-256 next key (generated before upgrade)
        assert_eq!(new_current.algorithm(), VerificationKeyCode::Secp256r1);

        provider.commit().await.unwrap();

        // After one more rotation, current will be ML-DSA-65
        let (ml_dsa_current, _) = provider.stage_rotation().await.unwrap();
        assert_eq!(ml_dsa_current.algorithm(), VerificationKeyCode::MlDsa65);

        provider.commit().await.unwrap();
        assert_eq!(
            provider.current_public_key().await.unwrap().algorithm(),
            VerificationKeyCode::MlDsa65
        );
    }
}
