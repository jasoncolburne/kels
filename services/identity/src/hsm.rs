//! HSM Client - PKCS#11 interface for hardware security modules

use std::sync::{Arc, Mutex};

use tokio::sync::RwLock;

use async_trait::async_trait;
use cesr::{Matter, PublicKey, Signature, SignatureCode, SigningKeyCode};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{Mechanism, dsa::HedgeType, dsa::SignAdditionalContext},
    object::{Attribute, AttributeType, ObjectClass},
    session::Session,
    types::AuthPin,
};
use kels::{KelsError, KeyProvider, compute_rotation_hash};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyHandle(String);

impl KeyHandle {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for KeyHandle {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for KeyHandle {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[async_trait]
pub trait HsmOperations: Send + Sync {
    async fn generate_keypair(
        &self,
        label: &str,
        algorithm: &str,
    ) -> Result<(KeyHandle, PublicKey), KelsError>;
    async fn get_public_key(&self, handle: &KeyHandle) -> Result<PublicKey, KelsError>;
    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Signature, KelsError>;
}

pub struct Pkcs11Client {
    _pkcs11: Arc<Pkcs11>,
    session: Mutex<Session>,
}

impl Pkcs11Client {
    pub fn new(library_path: &str, slot_index: usize, pin: &str) -> Result<Self, KelsError> {
        let pkcs11 = Pkcs11::new(library_path)
            .map_err(|e| KelsError::HardwareError(format!("PKCS#11 init failed: {}", e)))?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| KelsError::HardwareError(format!("PKCS#11 init failed: {}", e)))?;
        let slots = pkcs11
            .get_slots_with_token()
            .map_err(|e| KelsError::HardwareError(format!("No slots: {}", e)))?;
        let slot = slots
            .get(slot_index)
            .copied()
            .ok_or_else(|| KelsError::HardwareError("No slot available".into()))?;
        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| KelsError::HardwareError(format!("Session failed: {}", e)))?;
        session
            .login(
                cryptoki::session::UserType::User,
                Some(&AuthPin::new(pin.into())),
            )
            .map_err(|e| KelsError::HardwareError(format!("Login failed: {}", e)))?;
        Ok(Self {
            _pkcs11: Arc::new(pkcs11),
            session: Mutex::new(session),
        })
    }
}

#[async_trait]
impl HsmOperations for Pkcs11Client {
    async fn generate_keypair(
        &self,
        label: &str,
        _algorithm: &str,
    ) -> Result<(KeyHandle, PublicKey), KelsError> {
        let session = self
            .session
            .lock()
            .map_err(|e| KelsError::HardwareError(format!("Session lock failed: {}", e)))?;

        let pub_template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let priv_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Sign(true),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let (pub_handle, _priv_handle) = session
            .generate_key_pair(&Mechanism::MlDsaKeyPairGen, &pub_template, &priv_template)
            .map_err(|e| KelsError::KeyGenerationFailed(format!("PKCS#11 keygen failed: {}", e)))?;

        let attrs = session
            .get_attributes(pub_handle, &[AttributeType::Value])
            .map_err(|e| {
                KelsError::KeyGenerationFailed(format!("Failed to get public key: {}", e))
            })?;

        let value_bytes = attrs
            .into_iter()
            .find_map(|a| {
                if let Attribute::Value(v) = a {
                    Some(v)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                KelsError::KeyGenerationFailed("CKA_VALUE not found on public key".into())
            })?;

        let public_key = PublicKey::from_raw(SigningKeyCode::MlDsa65, value_bytes)
            .map_err(|e| KelsError::KeyGenerationFailed(e.to_string()))?;

        Ok((KeyHandle::new(label), public_key))
    }

    async fn get_public_key(&self, handle: &KeyHandle) -> Result<PublicKey, KelsError> {
        let session = self
            .session
            .lock()
            .map_err(|e| KelsError::HardwareError(format!("Session lock failed: {}", e)))?;

        let template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(handle.as_str().as_bytes().to_vec()),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| KelsError::HsmKeyNotFound(format!("Find failed: {}", e)))?;

        let obj_handle = objects
            .first()
            .ok_or_else(|| KelsError::HsmKeyNotFound(handle.as_str().to_string()))?;

        let attrs = session
            .get_attributes(*obj_handle, &[AttributeType::Value])
            .map_err(|e| KelsError::HardwareError(format!("Get attributes failed: {}", e)))?;

        let value_bytes = attrs
            .into_iter()
            .find_map(|a| {
                if let Attribute::Value(v) = a {
                    Some(v)
                } else {
                    None
                }
            })
            .ok_or_else(|| KelsError::HsmKeyNotFound("CKA_VALUE not found".into()))?;

        PublicKey::from_raw(SigningKeyCode::MlDsa65, value_bytes)
            .map_err(|e| KelsError::CryptoError(e.to_string()))
    }

    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Signature, KelsError> {
        let session = self
            .session
            .lock()
            .map_err(|e| KelsError::HardwareError(format!("Session lock failed: {}", e)))?;

        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(handle.as_str().as_bytes().to_vec()),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| KelsError::HsmKeyNotFound(format!("Find failed: {}", e)))?;

        let priv_handle = objects
            .first()
            .ok_or_else(|| KelsError::HsmKeyNotFound(handle.as_str().to_string()))?;

        let ctx = SignAdditionalContext::new(HedgeType::Preferred, None);
        let sig_bytes = session
            .sign(&Mechanism::MlDsa(ctx), *priv_handle, data)
            .map_err(|e| KelsError::SigningFailed(format!("PKCS#11 sign failed: {}", e)))?;

        Signature::from_raw(SignatureCode::MlDsa65, sig_bytes)
            .map_err(|e| KelsError::SigningFailed(e.to_string()))
    }
}

/// HSM-backed key provider with two-phase rotation support.
///
/// Uses vector-based key handle storage where:
/// - key_handles[len-2] = current key
/// - key_handles[len-1] = next key
/// - len > 2 means rotation is staged
///
/// Same pattern for recovery_handles:
/// - recovery_handles[0] = current recovery key
/// - len > 1 means recovery rotation is staged
pub struct HsmKeyProvider {
    hsm: Arc<dyn HsmOperations>,
    label_prefix: String,
    signing_generation: RwLock<u64>,
    recovery_generation: RwLock<u64>,
    key_handles: RwLock<Vec<KeyHandle>>,
    recovery_handles: RwLock<Vec<KeyHandle>>,
}

impl std::fmt::Debug for HsmKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmKeyProvider")
            .field("label_prefix", &self.label_prefix)
            .finish_non_exhaustive()
    }
}

impl Clone for HsmKeyProvider {
    fn clone(&self) -> Self {
        let signing_gen = *self.signing_generation.blocking_read();
        let recovery_gen = *self.recovery_generation.blocking_read();
        let key_handles = self.key_handles.blocking_read().clone();
        let recovery_handles = self.recovery_handles.blocking_read().clone();

        Self {
            hsm: Arc::clone(&self.hsm),
            label_prefix: self.label_prefix.clone(),
            signing_generation: RwLock::new(signing_gen),
            recovery_generation: RwLock::new(recovery_gen),
            key_handles: RwLock::new(key_handles),
            recovery_handles: RwLock::new(recovery_handles),
        }
    }
}

impl HsmKeyProvider {
    pub fn new(
        hsm: Arc<dyn HsmOperations>,
        label_prefix: &str,
        signing_generation: u64,
        recovery_generation: u64,
    ) -> Self {
        Self {
            hsm,
            label_prefix: label_prefix.to_string(),
            signing_generation: RwLock::new(signing_generation),
            recovery_generation: RwLock::new(recovery_generation),
            key_handles: RwLock::new(Vec::new()),
            recovery_handles: RwLock::new(Vec::new()),
        }
    }

    /// Restore from persisted state.
    pub fn with_handles(
        hsm: Arc<dyn HsmOperations>,
        label_prefix: &str,
        signing_generation: u64,
        recovery_generation: u64,
        current_handle: KeyHandle,
        next_handle: KeyHandle,
        recovery_handle: KeyHandle,
    ) -> Self {
        Self {
            hsm,
            label_prefix: label_prefix.to_string(),
            signing_generation: RwLock::new(signing_generation),
            recovery_generation: RwLock::new(recovery_generation),
            key_handles: RwLock::new(vec![current_handle, next_handle]),
            recovery_handles: RwLock::new(vec![recovery_handle]),
        }
    }

    async fn generate_signing_key(&self) -> Result<(KeyHandle, PublicKey), KelsError> {
        let mut generation = self.signing_generation.write().await;
        let label = format!("{}-{}", self.label_prefix, *generation);
        *generation += 1;
        self.hsm.generate_keypair(&label, "ml-dsa-65").await
    }

    async fn generate_recovery_key(&self) -> Result<(KeyHandle, PublicKey), KelsError> {
        let mut generation = self.recovery_generation.write().await;
        let label = format!("{}-recovery-{}", self.label_prefix, *generation);
        *generation += 1;
        self.hsm.generate_keypair(&label, "ml-dsa-65").await
    }
}

#[async_trait]
impl KeyProvider for HsmKeyProvider {
    async fn signing_generation(&self) -> u64 {
        *self.signing_generation.read().await
    }

    async fn recovery_generation(&self) -> u64 {
        *self.recovery_generation.read().await
    }

    async fn current_handle(&self) -> Option<String> {
        let key_handles = self.key_handles.read().await;
        if key_handles.len() >= 2 {
            key_handles
                .get(key_handles.len() - 2)
                .map(|h| h.as_str().to_string())
        } else {
            None
        }
    }

    async fn next_handle(&self) -> Option<String> {
        let key_handles = self.key_handles.read().await;
        key_handles.last().map(|h| h.as_str().to_string())
    }

    async fn recovery_handle(&self) -> Option<String> {
        let recovery_handles = self.recovery_handles.read().await;
        recovery_handles.first().map(|h| h.as_str().to_string())
    }

    async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoCurrentKey);
        }

        let key_handles = self.key_handles.read().await;
        let index = key_handles.len() - 2;
        let handle = key_handles.get(index).ok_or(KelsError::HsmKeyNotFound(
            "Current key not found".to_string(),
        ))?;
        self.hsm.get_public_key(handle).await
    }

    async fn generate_initial_keys(&mut self) -> Result<(PublicKey, String, String), KelsError> {
        let (current_handle, current_pub) = self.generate_signing_key().await?;
        let (next_handle, next_pub) = self.generate_signing_key().await?;
        let (recovery_handle, recovery_pub) = self.generate_recovery_key().await?;

        let next_hash = compute_rotation_hash(&next_pub.qb64());
        let recovery_hash = compute_rotation_hash(&recovery_pub.qb64());

        let mut key_handles = self.key_handles.write().await;
        *key_handles = vec![current_handle, next_handle];

        let mut recovery_handles = self.recovery_handles.write().await;
        *recovery_handles = vec![recovery_handle];

        Ok((current_pub, next_hash, recovery_hash))
    }

    async fn has_current(&self) -> bool {
        !self.key_handles.read().await.is_empty()
    }

    async fn has_next(&self) -> bool {
        self.key_handles.read().await.len() > 1
    }

    async fn has_staged(&self) -> bool {
        self.key_handles.read().await.len() > 2
    }

    async fn has_recovery(&self) -> bool {
        !self.recovery_handles.read().await.is_empty()
    }

    async fn has_staged_recovery(&self) -> bool {
        self.recovery_handles.read().await.len() > 1
    }

    async fn commit(&mut self) -> Result<(), KelsError> {
        if !self.has_staged().await {
            return Err(KelsError::NoStagedKey);
        }

        if self.has_staged_recovery().await {
            let mut recovery_handles = self.recovery_handles.write().await;
            let length = recovery_handles.len();
            *recovery_handles = recovery_handles[(length - 1)..].to_vec();
        }

        let mut key_handles = self.key_handles.write().await;
        let length = key_handles.len();
        *key_handles = key_handles[(length - 2)..].to_vec();

        Ok(())
    }

    async fn stage_rotation(&mut self) -> Result<(PublicKey, String), KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoNextKey);
        }

        let new_current_pub = {
            let key_handles = self.key_handles.read().await;
            let length = key_handles.len();
            let handle = &key_handles[length - 1];
            self.hsm.get_public_key(handle).await?
        };

        let (new_next_handle, new_next_pub) = self.generate_signing_key().await?;
        let mut key_handles = self.key_handles.write().await;
        key_handles.push(new_next_handle);

        let next_hash = compute_rotation_hash(&new_next_pub.qb64());

        Ok((new_current_pub, next_hash))
    }

    async fn stage_recovery_rotation(&mut self) -> Result<(PublicKey, String), KelsError> {
        if !self.has_recovery().await {
            return Err(KelsError::NoRecoveryKey);
        }

        if self.has_staged_recovery().await {
            return Err(KelsError::AlreadyStagedRecovery);
        }

        let current_recovery = {
            let recovery_handles = self.recovery_handles.read().await;
            let handle = &recovery_handles[0];
            self.hsm.get_public_key(handle).await?
        };

        let (new_recovery_handle, new_recovery_pub) = self.generate_recovery_key().await?;
        let mut recovery_handles = self.recovery_handles.write().await;
        recovery_handles.push(new_recovery_handle);

        let recovery_hash = compute_rotation_hash(&new_recovery_pub.qb64());

        Ok((current_recovery, recovery_hash))
    }

    async fn rollback(&mut self) -> Result<(), KelsError> {
        if !self.has_staged().await {
            return Err(KelsError::NoStagedKey);
        }

        if self.has_staged_recovery().await {
            let mut recovery_handles = self.recovery_handles.write().await;
            let mut generation = self.recovery_generation.write().await;

            *generation -= (recovery_handles.len() as u64) - 1;
            *recovery_handles = recovery_handles[..1].to_vec();
        }

        let mut key_handles = self.key_handles.write().await;
        let mut generation = self.signing_generation.write().await;

        *generation -= (key_handles.len() as u64) - 2;
        *key_handles = key_handles[..2].to_vec();

        Ok(())
    }

    async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        if !self.has_next().await {
            return Err(KelsError::NoCurrentKey);
        }

        let key_handles = self.key_handles.read().await;
        let length = key_handles.len();
        let handle = &key_handles[length - 2];

        self.hsm.sign(handle, data).await
    }

    async fn sign_with_recovery(&self, data: &[u8]) -> Result<Signature, KelsError> {
        if !self.has_recovery().await {
            return Err(KelsError::NoRecoveryKey);
        }

        let recovery_handles = self.recovery_handles.read().await;
        let handle = &recovery_handles[0];

        self.hsm.sign(handle, data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    // ==================== KeyHandle Tests ====================

    #[test]
    fn test_key_handle_new() {
        let handle = KeyHandle::new("my-key");
        assert_eq!(handle.as_str(), "my-key");
    }

    #[test]
    fn test_key_handle_new_with_string() {
        let handle = KeyHandle::new(String::from("my-key"));
        assert_eq!(handle.as_str(), "my-key");
    }

    #[test]
    fn test_key_handle_from_string() {
        let handle: KeyHandle = String::from("key-123").into();
        assert_eq!(handle.as_str(), "key-123");
    }

    #[test]
    fn test_key_handle_from_str() {
        let handle: KeyHandle = "key-456".into();
        assert_eq!(handle.as_str(), "key-456");
    }

    #[test]
    fn test_key_handle_equality() {
        let h1 = KeyHandle::new("same");
        let h2 = KeyHandle::new("same");
        let h3 = KeyHandle::new("different");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_key_handle_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(KeyHandle::new("key1"));
        set.insert(KeyHandle::new("key1")); // duplicate
        set.insert(KeyHandle::new("key2"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_key_handle_clone() {
        let h1 = KeyHandle::new("test");
        let h2 = h1.clone();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_key_handle_debug() {
        let handle = KeyHandle::new("debug-key");
        let debug_str = format!("{:?}", handle);
        assert!(debug_str.contains("debug-key"));
    }

    // ==================== Mock HsmOperations ====================

    struct MockHsm {
        keys: Mutex<HashMap<String, String>>, // label -> public_key_qb64
        seeds: Mutex<HashMap<String, [u8; 32]>>, // label -> seed for key derivation
        call_count: Mutex<usize>,
    }

    impl MockHsm {
        fn new() -> Self {
            Self {
                keys: Mutex::new(HashMap::new()),
                seeds: Mutex::new(HashMap::new()),
                call_count: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl HsmOperations for MockHsm {
        async fn generate_keypair(
            &self,
            label: &str,
            _algorithm: &str,
        ) -> Result<(KeyHandle, PublicKey), KelsError> {
            let mut count = self.call_count.lock().await;
            *count += 1;

            // Generate a deterministic ML-DSA-65 keypair from seed
            use fips204::ml_dsa_65;
            use fips204::traits::{KeyGen, SerDes};

            let mut seed = [0u8; 32];
            for (i, b) in label.bytes().enumerate() {
                seed[i % 32] ^= b;
            }
            seed[0] = seed[0].wrapping_add(*count as u8);

            let (pk, _sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
            let pk_bytes = pk.into_bytes().to_vec();

            let public_key = PublicKey::from_raw(cesr::SigningKeyCode::MlDsa65, pk_bytes)
                .map_err(|e| KelsError::KeyGenerationFailed(e.to_string()))?;

            let mut keys = self.keys.lock().await;
            keys.insert(label.to_string(), public_key.qb64());

            let mut seeds = self.seeds.lock().await;
            seeds.insert(label.to_string(), seed);

            Ok((KeyHandle::new(label), public_key))
        }

        async fn get_public_key(&self, handle: &KeyHandle) -> Result<PublicKey, KelsError> {
            let keys = self.keys.lock().await;
            let qb64 = keys
                .get(handle.as_str())
                .ok_or_else(|| KelsError::HsmKeyNotFound(handle.as_str().to_string()))?;
            PublicKey::from_qb64(qb64).map_err(|e| KelsError::CryptoError(e.to_string()))
        }

        async fn sign(&self, handle: &KeyHandle, _data: &[u8]) -> Result<Signature, KelsError> {
            // Verify key exists
            let keys = self.keys.lock().await;
            if !keys.contains_key(handle.as_str()) {
                return Err(KelsError::HsmKeyNotFound(handle.as_str().to_string()));
            }

            // Return a mock signature (valid CESR ML-DSA-65 format)
            let sig_bytes = vec![1u8; 3309];
            Signature::from_raw(cesr::SignatureCode::MlDsa65, sig_bytes)
                .map_err(|e| KelsError::SigningFailed(e.to_string()))
        }
    }

    // ==================== HsmKeyProvider Tests ====================

    #[tokio::test]
    async fn test_hsm_key_provider_new() {
        let mock = Arc::new(MockHsm::new());
        let provider = HsmKeyProvider::new(mock, "test-prefix", 0, 0);

        assert!(!provider.has_current().await);
        assert!(!provider.has_next().await);
        assert!(!provider.has_staged().await);
        assert!(!provider.has_recovery().await);
        assert!(!provider.has_staged_recovery().await);
    }

    #[tokio::test]
    async fn test_hsm_key_provider_with_handles() {
        let mock = Arc::new(MockHsm::new());

        // Pre-populate mock with keys
        let _ = mock.generate_keypair("current", "ml-dsa-65").await;
        let _ = mock.generate_keypair("next", "ml-dsa-65").await;
        let _ = mock.generate_keypair("recovery", "ml-dsa-65").await;

        let provider = HsmKeyProvider::with_handles(
            mock,
            "test-prefix",
            2,
            1,
            KeyHandle::new("current"),
            KeyHandle::new("next"),
            KeyHandle::new("recovery"),
        );

        assert!(provider.has_current().await);
        assert!(provider.has_next().await);
        assert!(!provider.has_staged().await);
        assert!(provider.has_recovery().await);
        assert!(!provider.has_staged_recovery().await);
    }

    #[tokio::test]
    async fn test_hsm_key_provider_signing_generation() {
        let mock = Arc::new(MockHsm::new());
        let provider = HsmKeyProvider::new(mock, "prefix", 42, 10);

        assert_eq!(provider.signing_generation().await, 42);
        assert_eq!(provider.recovery_generation().await, 10);
    }

    #[tokio::test]
    async fn test_hsm_key_provider_generate_initial_keys() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        let result = provider.generate_initial_keys().await;
        assert!(result.is_ok());

        let (public_key, next_hash, recovery_hash) = result.unwrap();
        assert!(!public_key.qb64().is_empty());
        assert!(!next_hash.is_empty());
        assert!(!recovery_hash.is_empty());

        assert!(provider.has_current().await);
        assert!(provider.has_next().await);
        assert!(provider.has_recovery().await);
        assert_eq!(provider.signing_generation().await, 2); // 0->1->2
        assert_eq!(provider.recovery_generation().await, 1); // 0->1
    }

    #[tokio::test]
    async fn test_hsm_key_provider_current_handle() {
        let mock = Arc::new(MockHsm::new());
        let _ = mock.generate_keypair("curr", "ml-dsa-65").await;
        let _ = mock.generate_keypair("nxt", "ml-dsa-65").await;

        let provider = HsmKeyProvider::with_handles(
            mock,
            "p",
            2,
            0,
            KeyHandle::new("curr"),
            KeyHandle::new("nxt"),
            KeyHandle::new("rec"),
        );

        assert_eq!(provider.current_handle().await, Some("curr".to_string()));
        assert_eq!(provider.next_handle().await, Some("nxt".to_string()));
    }

    #[tokio::test]
    async fn test_hsm_key_provider_current_handle_empty() {
        let mock = Arc::new(MockHsm::new());
        let provider = HsmKeyProvider::new(mock, "p", 0, 0);

        assert_eq!(provider.current_handle().await, None);
        assert_eq!(provider.next_handle().await, None);
        assert_eq!(provider.recovery_handle().await, None);
    }

    #[tokio::test]
    async fn test_hsm_key_provider_current_public_key_no_key() {
        let mock = Arc::new(MockHsm::new());
        let provider = HsmKeyProvider::new(mock, "p", 0, 0);

        let result = provider.current_public_key().await;
        assert!(matches!(result, Err(KelsError::NoCurrentKey)));
    }

    #[tokio::test]
    async fn test_hsm_key_provider_stage_rotation() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        // Initialize first
        provider.generate_initial_keys().await.unwrap();
        assert!(!provider.has_staged().await);

        // Stage rotation
        let result = provider.stage_rotation().await;
        assert!(result.is_ok());
        assert!(provider.has_staged().await);
        assert_eq!(provider.signing_generation().await, 3); // one more key generated
    }

    #[tokio::test]
    async fn test_hsm_key_provider_stage_rotation_no_next() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        let result = provider.stage_rotation().await;
        assert!(matches!(result, Err(KelsError::NoNextKey)));
    }

    #[tokio::test]
    async fn test_hsm_key_provider_commit() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();
        provider.stage_rotation().await.unwrap();
        assert!(provider.has_staged().await);

        let result = provider.commit().await;
        assert!(result.is_ok());
        assert!(!provider.has_staged().await);
        assert!(provider.has_current().await);
        assert!(provider.has_next().await);
    }

    #[tokio::test]
    async fn test_hsm_key_provider_commit_no_staged() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();

        let result = provider.commit().await;
        assert!(matches!(result, Err(KelsError::NoStagedKey)));
    }

    #[tokio::test]
    async fn test_hsm_key_provider_rollback() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();
        let gen_before = provider.signing_generation().await;

        provider.stage_rotation().await.unwrap();
        assert!(provider.has_staged().await);

        let result = provider.rollback().await;
        assert!(result.is_ok());
        assert!(!provider.has_staged().await);
        assert_eq!(provider.signing_generation().await, gen_before);
    }

    #[tokio::test]
    async fn test_hsm_key_provider_rollback_no_staged() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();

        let result = provider.rollback().await;
        assert!(matches!(result, Err(KelsError::NoStagedKey)));
    }

    #[tokio::test]
    async fn test_hsm_key_provider_sign() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();

        let result = provider.sign(b"test data").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hsm_key_provider_sign_no_key() {
        let mock = Arc::new(MockHsm::new());
        let provider = HsmKeyProvider::new(mock, "test", 0, 0);

        let result = provider.sign(b"test data").await;
        assert!(matches!(result, Err(KelsError::NoCurrentKey)));
    }

    #[tokio::test]
    async fn test_hsm_key_provider_sign_with_recovery() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();

        let result = provider.sign_with_recovery(b"test data").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hsm_key_provider_sign_with_recovery_no_key() {
        let mock = Arc::new(MockHsm::new());
        let provider = HsmKeyProvider::new(mock, "test", 0, 0);

        let result = provider.sign_with_recovery(b"test data").await;
        assert!(matches!(result, Err(KelsError::NoRecoveryKey)));
    }

    #[tokio::test]
    async fn test_hsm_key_provider_stage_recovery_rotation() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();
        assert!(!provider.has_staged_recovery().await);

        let result = provider.stage_recovery_rotation().await;
        assert!(result.is_ok());
        assert!(provider.has_staged_recovery().await);
    }

    #[tokio::test]
    async fn test_hsm_key_provider_stage_recovery_rotation_no_recovery() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        let result = provider.stage_recovery_rotation().await;
        assert!(matches!(result, Err(KelsError::NoRecoveryKey)));
    }

    #[tokio::test]
    async fn test_hsm_key_provider_stage_recovery_rotation_already_staged() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();
        provider.stage_recovery_rotation().await.unwrap();

        let result = provider.stage_recovery_rotation().await;
        assert!(matches!(result, Err(KelsError::AlreadyStagedRecovery)));
    }

    #[tokio::test]
    async fn test_hsm_key_provider_commit_with_staged_recovery() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();
        provider.stage_rotation().await.unwrap();
        provider.stage_recovery_rotation().await.unwrap();

        assert!(provider.has_staged().await);
        assert!(provider.has_staged_recovery().await);

        let result = provider.commit().await;
        assert!(result.is_ok());
        assert!(!provider.has_staged().await);
        assert!(!provider.has_staged_recovery().await);
        assert!(provider.has_recovery().await);
    }

    #[tokio::test]
    async fn test_hsm_key_provider_rollback_with_staged_recovery() {
        let mock = Arc::new(MockHsm::new());
        let mut provider = HsmKeyProvider::new(mock, "test", 0, 0);

        provider.generate_initial_keys().await.unwrap();
        let recovery_gen_before = provider.recovery_generation().await;

        provider.stage_rotation().await.unwrap();
        provider.stage_recovery_rotation().await.unwrap();

        let result = provider.rollback().await;
        assert!(result.is_ok());
        assert!(!provider.has_staged().await);
        assert!(!provider.has_staged_recovery().await);
        assert_eq!(provider.recovery_generation().await, recovery_gen_before);
    }

    #[tokio::test]
    async fn test_hsm_key_provider_debug() {
        let mock = Arc::new(MockHsm::new());
        let provider = HsmKeyProvider::new(mock, "my-prefix", 0, 0);

        let debug_str = format!("{:?}", provider);
        assert!(debug_str.contains("HsmKeyProvider"));
        assert!(debug_str.contains("my-prefix"));
    }
}
