//! Caching & sync types

use cesr::{Digest, Matter};
use serde::{Deserialize, Serialize};

// Re-export for backwards compatibility — canonical location is crate::crypto::generate_nonce
pub use crate::crypto::generate_nonce;

/// Hash a domain-qualified label into a deterministic CESR-encoded Blake3 digest.
///
/// Used for deterministic effective SAIDs for divergent and contested KELs:
/// - `hash_effective_said("divergent:{prefix}")` — all divergent nodes agree
/// - `hash_effective_said("contested:{prefix}")` — all contested nodes agree
pub fn hash_effective_said(input: &str) -> String {
    Digest::blake3_256(input.as_bytes()).qb64()
}

/// Request payload for authenticated prefix listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedSelfAddressedRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// Request payload for authenticated admin operations.
///
/// Used with `SignedRequest<AdminRequest>` to authenticate admin CLI requests
/// against the registry's own identity (via HSM-backed signing).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRequest {
    pub timestamp: i64,
    pub nonce: String,
}

/// Response for paginated prefix listing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixListResponse {
    pub prefixes: Vec<PrefixState>,
    pub next_cursor: Option<String>,
}

/// A prefix with its latest SAID, used for bootstrap sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixState {
    pub prefix: String,
    pub said: String,
}
