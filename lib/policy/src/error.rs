use thiserror::Error;

#[derive(Error, Clone, Debug)]
pub enum PolicyError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("evaluation error: {0}")]
    EvaluationError(String),
    #[error("resolution error: {0}")]
    ResolutionError(String),
    /// #156: deferrable — the named Policy SAD object isn't present
    /// locally. Carries the SAID structurally so the verifier can
    /// classify as `KelsError::MissingSadObject` without parsing the
    /// `ResolutionError(String)` text. Resolver impls emit this when an
    /// underlying `ObjectStoreError::ObjectNotFound` lookup miss is
    /// observed during policy resolution.
    #[error("policy SAD object not found: {said}")]
    PolicyNotFound { said: cesr::Digest256 },
    #[error("JSON error: {0}")]
    JsonError(String),
    #[error("storage error: {0}")]
    StorageError(String),
    #[error("KEL error: {0}")]
    KelError(String),
}

impl From<serde_json::Error> for PolicyError {
    fn from(e: serde_json::Error) -> Self {
        PolicyError::JsonError(e.to_string())
    }
}

impl From<verifiable_storage::StorageError> for PolicyError {
    fn from(e: verifiable_storage::StorageError) -> Self {
        PolicyError::StorageError(e.to_string())
    }
}

impl From<kels_core::KelsError> for PolicyError {
    fn from(e: kels_core::KelsError) -> Self {
        PolicyError::KelError(e.to_string())
    }
}
