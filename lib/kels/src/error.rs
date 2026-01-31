//! KELS Error Types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum KelsError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("No current key available")]
    NoCurrentKey,

    #[error("No next key available")]
    NoNextKey,

    #[error("No recovery key available")]
    NoRecoveryKey,

    #[error("No staged key available")]
    NoStagedKey,

    #[error("No staged recovery key available")]
    NoStagedRecoveryKey,

    #[error("Currently staged keys")]
    CurrentlyStaged,

    #[error("Already staged recovery key")]
    AlreadyStagedRecovery,

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid key event: {0}")]
    InvalidKeyEvent(String),

    #[error("Invalid KEL: {0}")]
    InvalidKel(String),

    #[error("Not yet incepted")]
    NotIncepted,

    #[error("KEL is decommissioned")]
    KelDecommissioned,

    #[error("Submission failed: {0}")]
    SubmissionFailed(String),

    #[error("Offline mode: {0}")]
    OfflineMode(String),

    #[error("No recovery needed: {0}")]
    NoRecoveryNeeded(String),

    #[error("Key mismatch: {0}")]
    KeyMismatch(String),

    #[error("Divergence detected at: {diverged_at}, submission_accepted: {submission_accepted}")]
    DivergenceDetected {
        diverged_at: u64,
        submission_accepted: bool,
    },

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Contested KEL: {0}")]
    ContestedKel(String),

    #[error("Recovery protected: adversary used recovery key")]
    RecoveryProtected,

    #[error("KEL diverged at: {0}")]
    Diverged(String),

    #[error("KEL frozen and requires recovery")]
    Frozen,

    #[error("KEL recovery key revealed, contest required")]
    ContestRequired,

    #[error("Invalid SAID: {0}")]
    InvalidSaid(String),

    #[error("Invalid prefix: {0}")]
    InvalidPrefix(String),

    #[error("Invalid version: {0}")]
    InvalidVersion(String),

    #[error("Anchor verification failed: {0}")]
    AnchorVerificationFailed(String),

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

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::Matter;

    #[test]
    fn test_error_display() {
        let err = KelsError::KeyNotFound("test_key".to_string());
        assert!(err.to_string().contains("test_key"));

        let err = KelsError::NoCurrentKey;
        assert!(err.to_string().contains("current key"));

        let err = KelsError::DivergenceDetected {
            diverged_at: 5,
            submission_accepted: true,
        };
        assert!(err.to_string().contains("5"));
    }

    #[test]
    fn test_from_cesr_error() {
        // Create a CESR error by parsing invalid data
        let cesr_err = cesr::Signature::from_qb64("invalid").unwrap_err();
        let kels_err: KelsError = cesr_err.into();
        assert!(matches!(kels_err, KelsError::CryptoError(_)));
    }
}
