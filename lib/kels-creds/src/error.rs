use thiserror::Error;

#[derive(Error, Clone, Debug)]
pub enum CredentialError {
    #[error("Invalid SAID: {0}")]
    InvalidSaid(String),

    #[error("Invalid schema: {0}")]
    InvalidSchema(String),

    #[error("Invalid credential: {0}")]
    InvalidCredential(String),

    #[error("Invalid disclosure expression: {0}")]
    InvalidDisclosure(String),

    #[error("Compaction error: {0}")]
    CompactionError(String),

    #[error("Expansion error: {0}")]
    ExpansionError(String),

    #[error("Schema validation error: {0}")]
    SchemaValidationError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("JSON error: {0}")]
    JsonError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Reserved label: {0}")]
    ReservedLabel(String),
}

impl From<serde_json::Error> for CredentialError {
    fn from(e: serde_json::Error) -> Self {
        CredentialError::JsonError(e.to_string())
    }
}

impl From<cesr::CesrError> for CredentialError {
    fn from(e: cesr::CesrError) -> Self {
        CredentialError::CryptoError(e.to_string())
    }
}

impl From<verifiable_storage::StorageError> for CredentialError {
    fn from(e: verifiable_storage::StorageError) -> Self {
        CredentialError::StorageError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::Matter;

    #[test]
    fn test_error_display() {
        let err = CredentialError::InvalidSaid("bad said".to_string());
        assert!(err.to_string().contains("bad said"));

        let err = CredentialError::ReservedLabel("said".to_string());
        assert!(err.to_string().contains("said"));
    }

    #[test]
    fn test_error_variants_display() {
        let errors: Vec<CredentialError> = vec![
            CredentialError::InvalidSaid("test".to_string()),
            CredentialError::InvalidSchema("test".to_string()),
            CredentialError::InvalidCredential("test".to_string()),
            CredentialError::InvalidDisclosure("test".to_string()),
            CredentialError::CompactionError("test".to_string()),
            CredentialError::ExpansionError("test".to_string()),
            CredentialError::SchemaValidationError("test".to_string()),
            CredentialError::VerificationError("test".to_string()),
            CredentialError::JsonError("test".to_string()),
            CredentialError::CryptoError("test".to_string()),
            CredentialError::StorageError("test".to_string()),
            CredentialError::ReservedLabel("test".to_string()),
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_from_json_error() {
        let json_result: Result<String, serde_json::Error> = serde_json::from_str("invalid");
        let json_err = json_result.unwrap_err();
        let cred_err: CredentialError = json_err.into();
        assert!(matches!(cred_err, CredentialError::JsonError(_)));
    }

    #[test]
    fn test_from_cesr_error() {
        let cesr_err = cesr::Signature::from_qb64("invalid").unwrap_err();
        let cred_err: CredentialError = cesr_err.into();
        assert!(matches!(cred_err, CredentialError::CryptoError(_)));
    }

    #[test]
    fn test_from_storage_error() {
        let json_result: Result<String, serde_json::Error> = serde_json::from_str("invalid");
        let storage_err =
            verifiable_storage::StorageError::SerializationError(json_result.unwrap_err());
        let cred_err: CredentialError = storage_err.into();
        assert!(matches!(cred_err, CredentialError::StorageError(_)));
    }
}
