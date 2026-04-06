//! Exchange protocol error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("ESSR seal failed: {0}")]
    SealFailed(String),

    #[error("ESSR open failed: {0}")]
    OpenFailed(String),

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("SAID verification failed: {0}")]
    SaidVerification(String),

    #[error("sender mismatch: envelope sender {envelope} != inner sender {inner}")]
    SenderMismatch { envelope: String, inner: String },

    #[error("invalid exchange message: {0}")]
    InvalidMessage(String),

    #[error("invalid key publication: {0}")]
    InvalidKeyPublication(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("KEL error: {0}")]
    KelError(String),

    #[error("crypto error: {0}")]
    CryptoError(String),
}

impl From<serde_json::Error> for ExchangeError {
    fn from(e: serde_json::Error) -> Self {
        ExchangeError::Serialization(e.to_string())
    }
}

impl From<kels_core::KelsError> for ExchangeError {
    fn from(e: kels_core::KelsError) -> Self {
        ExchangeError::KelError(e.to_string())
    }
}
