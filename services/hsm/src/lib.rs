//! HSM Service - SoftHSM2 PKCS#11 wrapper
//!
//! This service wraps SoftHSM2 via cryptoki and exposes cryptographic
//! operations over a REST API. Keys are identified by their label,
//! which persists across restarts.
//!
//! Key features:
//! - secp256r1 (P-256) key generation
//! - ECDSA signing
//! - Persistent key storage via SoftHSM2

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod handlers;
pub mod pkcs11;
pub mod server;

pub use pkcs11::HsmContext;
