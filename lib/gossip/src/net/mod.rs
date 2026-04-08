//! Networking layer for the KELS gossip protocol.
//!
//! This module provides the transport and actor infrastructure that connects the IO-free
//! protocol state machine ([`crate::proto`]) to the network.
//!
//! ## Architecture
//!
//! ```text
//! Application (commands, events)
//!         |
//!    GossipActor (event loop)
//!         |
//!    EncryptedStream (AES-GCM-256)
//!         |
//!    TCP (reliable transport)
//! ```
//!
//! ## Trait abstractions
//!
//! The networking layer is parameterized over [`Signer`] and [`PeerVerifier`] traits,
//! which bridge to the KELS signing infrastructure without creating a direct dependency
//! on the kels library.

pub mod actor;
pub mod codec;
pub mod crypto;
pub mod transport;

use std::future::Future;


/// Error type for networking and gossip operations.
#[derive(Debug)]
pub enum Error {
    /// IO error from the transport layer.
    Io(std::io::Error),
    /// Handshake protocol error.
    Handshake(String),
    /// Peer identity verification failed.
    VerificationFailed(String),
    /// Encryption/decryption error.
    Crypto(String),
    /// Message serialization/deserialization error.
    Codec(String),
    /// The gossip actor has shut down.
    Shutdown,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {e}"),
            Error::Handshake(msg) => write!(f, "handshake failed: {msg}"),
            Error::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
            Error::Crypto(msg) => write!(f, "crypto error: {msg}"),
            Error::Codec(msg) => write!(f, "codec error: {msg}"),
            Error::Shutdown => write!(f, "gossip actor shut down"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Trait for signing handshake data.
///
/// Implementations bridge to KELS signing infrastructure (software keys or HSM).
/// The gossip crate is agnostic to CESR encoding — the implementer handles encoding
/// internally and returns raw bytes.
pub trait Signer: Send + Sync + 'static {
    /// Our node identity (KELS prefix).
    fn node_prefix(&self) -> cesr::Digest;

    /// Sign the given data. Returns the signature as raw bytes.
    fn sign(&self, data: &[u8]) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;

    /// KEM algorithm for handshake key exchange.
    /// Default: ML-KEM-1024 (fail secure). Implementations may relax to ML-KEM-768
    /// after verifying no peer in the federation uses ML-DSA-87.
    fn kem_algorithm(&self) -> cesr::EncapsulationKeyCode {
        cesr::EncapsulationKeyCode::MlKem1024
    }
}

/// Trait for verifying peer identity during handshake.
///
/// Implementations look up the peer's current public key from their KEL, verify
/// the signature, and handle key rotation (re-fetching the KEL on mismatch).
pub trait PeerVerifier: Send + Sync + 'static {
    /// Verify a peer's handshake signature.
    ///
    /// The implementation must:
    /// 1. Check the peer is authorized (prefix in allowlist)
    /// 2. Look up the peer's KEL to get the current public key
    /// 3. Verify the signature against the KEL key
    /// 4. On verification failure (rotation), re-fetch the KEL and retry
    fn verify_peer(
        &self,
        peer: &cesr::Digest,
        data: &[u8],
        signature: &[u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;
}
