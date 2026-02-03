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

    #[error("Server error ({1:?}): {0}")]
    ServerError(String, crate::types::ErrorCode),

    #[error("Missing keys for provider")]
    MissingKeys,

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

    #[error("No ready nodes available in registry")]
    NoReadyNodes,

    #[error("All registries failed: {0}")]
    AllRegistriesFailed(String),
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

    #[test]
    fn test_error_variants_display() {
        // Test all error variants have proper display messages
        let errors: Vec<KelsError> = vec![
            KelsError::NoNextKey,
            KelsError::NoRecoveryKey,
            KelsError::NoStagedKey,
            KelsError::NoStagedRecoveryKey,
            KelsError::CurrentlyStaged,
            KelsError::AlreadyStagedRecovery,
            KelsError::InvalidSignature("bad sig".to_string()),
            KelsError::InvalidKeyEvent("bad event".to_string()),
            KelsError::InvalidKel("bad kel".to_string()),
            KelsError::NotIncepted,
            KelsError::KelDecommissioned,
            KelsError::SubmissionFailed("failed".to_string()),
            KelsError::OfflineMode("offline".to_string()),
            KelsError::NoRecoveryNeeded("no recovery".to_string()),
            KelsError::KeyMismatch("mismatch".to_string()),
            KelsError::SignatureVerificationFailed,
            KelsError::VerificationFailed("verify failed".to_string()),
            KelsError::SigningFailed("sign failed".to_string()),
            KelsError::KeyGenerationFailed("keygen failed".to_string()),
            KelsError::MissingKeys,
            KelsError::CryptoError("crypto error".to_string()),
            KelsError::CacheError("cache error".to_string()),
            KelsError::StorageError("storage error".to_string()),
            KelsError::ContestedKel("contested".to_string()),
            KelsError::RecoveryProtected,
            KelsError::Diverged("diverged".to_string()),
            KelsError::Frozen,
            KelsError::ContestRequired,
            KelsError::InvalidSaid("bad said".to_string()),
            KelsError::InvalidPrefix("bad prefix".to_string()),
            KelsError::InvalidVersion("bad version".to_string()),
            KelsError::AnchorVerificationFailed("anchor failed".to_string()),
            KelsError::HardwareError("hw error".to_string()),
            KelsError::NoReadyNodes,
            KelsError::AllRegistriesFailed("all failed".to_string()),
        ];

        for err in errors {
            // Just ensure Display doesn't panic and produces non-empty output
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_server_error_with_code() {
        use crate::types::ErrorCode;

        let err = KelsError::ServerError("not found".to_string(), ErrorCode::NotFound);
        let msg = err.to_string();
        assert!(msg.contains("not found"));
        assert!(msg.contains("NotFound"));
    }

    #[test]
    fn test_divergence_detected_fields() {
        let err = KelsError::DivergenceDetected {
            diverged_at: 10,
            submission_accepted: false,
        };
        let msg = err.to_string();
        assert!(msg.contains("10"));
        assert!(msg.contains("false"));
    }

    #[test]
    fn test_from_storage_error() {
        // Create a storage error by triggering a JSON parse error
        let json_err: Result<String, serde_json::Error> = serde_json::from_str("invalid");
        let storage_err =
            verifiable_storage::StorageError::SerializationError(json_err.unwrap_err());
        let kels_err: KelsError = storage_err.into();
        assert!(matches!(kels_err, KelsError::StorageError(_)));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let kels_err: KelsError = io_err.into();
        assert!(matches!(kels_err, KelsError::IoError(_)));
    }

    #[test]
    fn test_from_json_error() {
        let json_result: Result<String, serde_json::Error> = serde_json::from_str("invalid json");
        let json_err = json_result.unwrap_err();
        let kels_err: KelsError = json_err.into();
        assert!(matches!(kels_err, KelsError::JsonError(_)));
    }
}
