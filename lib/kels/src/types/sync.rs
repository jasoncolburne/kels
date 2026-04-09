//! Caching & sync types

use cesr::Digest256;
use serde::{Deserialize, Serialize};

/// Hash a domain-qualified label into a deterministic CESR-encoded Blake3 digest.
///
/// Used for deterministic effective SAIDs for divergent and contested KELs:
/// - `hash_effective_said("divergent:{prefix}")` — all divergent nodes agree
/// - `hash_effective_said("contested:{prefix}")` — all contested nodes agree
pub fn hash_effective_said(input: &str) -> cesr::Digest256 {
    Digest256::blake3_256(input.as_bytes())
}

/// Request payload for authenticated prefix listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedSelfAddressedRequest {
    pub timestamp: i64,
    pub nonce: cesr::Nonce256,
    pub cursor: Option<cesr::Digest256>,
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
    pub nonce: cesr::Nonce256,
}

/// Response for paginated prefix listing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixListResponse {
    pub prefixes: Vec<PrefixState>,
    pub next_cursor: Option<cesr::Digest256>,
}

/// A prefix with its latest SAID, used for bootstrap sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixState {
    pub prefix: cesr::Digest256,
    pub said: cesr::Digest256,
}
