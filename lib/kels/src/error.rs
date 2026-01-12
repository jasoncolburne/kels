//! KELS Error Types

use thiserror::Error;

/// Errors that can occur during KELS operations
#[derive(Error, Debug)]
pub enum KelsError {
    /// Key not found in storage
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// No current key available
    #[error("No current key available")]
    NoCurrentKey,

    /// No next key available
    #[error("No next key available")]
    NoNextKey,

    /// No recovery key available
    #[error("No recovery key available")]
    NoRecoveryKey,

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid key event
    #[error("Invalid key event: {0}")]
    InvalidKeyEvent(String),

    /// Invalid KEL structure
    #[error("Invalid KEL: {0}")]
    InvalidKel(String),

    /// Not yet incepted
    #[error("Not yet incepted")]
    NotIncepted,

    /// KEL is decommissioned
    #[error("KEL is decommissioned")]
    KelDecommissioned,

    /// Event submission failed
    #[error("Submission failed: {0}")]
    SubmissionFailed(String),

    /// Operation not available in offline mode
    #[error("Offline mode: {0}")]
    OfflineMode(String),

    /// No recovery needed
    #[error("No recovery needed: {0}")]
    NoRecoveryNeeded(String),

    /// Key mismatch
    #[error("Key mismatch: {0}")]
    KeyMismatch(String),

    /// Divergence detected
    #[error("Divergence detected at: {0}")]
    DivergenceDetected(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Server error from KELS service
    #[error("Server error: {0}")]
    ServerError(String),

    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// KEL is contested (both parties revealed recovery keys)
    #[error("KEL contested: {0}")]
    Contested(String),

    /// Contested KEL (cannot perform operations)
    #[error("Contested KEL: {0}")]
    ContestedKel(String),

    /// KEL divergence detected
    #[error("KEL diverged at: {0}")]
    Diverged(String),

    /// Invalid SAID (self-addressing identifier)
    #[error("Invalid SAID: {0}")]
    InvalidSaid(String),

    /// Invalid prefix
    #[error("Invalid prefix: {0}")]
    InvalidPrefix(String),

    /// Invalid version chain
    #[error("Invalid version: {0}")]
    InvalidVersion(String),

    /// Anchor verification failed
    #[error("Anchor verification failed: {0}")]
    AnchorVerificationFailed(String),

    /// Hardware error (Secure Enclave, HSM, etc.)
    #[error("Hardware error: {0}")]
    HardwareError(String),
}

impl From<cesr::CesrError> for KelsError {
    fn from(e: cesr::CesrError) -> Self {
        KelsError::CryptoError(e.to_string())
    }
}

impl From<verifiable_storage::StorageError> for KelsError {
    fn from(e: verifiable_storage::StorageError) -> Self {
        KelsError::StorageError(e.to_string())
    }
}
