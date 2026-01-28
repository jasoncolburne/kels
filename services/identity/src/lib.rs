//! Identity Service - HSM-backed key management for KELS registry
//!
//! This service manages the KELS registry's cryptographic identity using
//! hardware security modules (HSM).
//!
//! Key responsibilities:
//! - Manage registry KEL (inception, rotation)
//! - Sign data on behalf of the registry
//! - Anchor SAIDs in the registry's KEL

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod handlers;
pub mod hsm;
pub mod repository;
pub mod server;

pub use server::run;
