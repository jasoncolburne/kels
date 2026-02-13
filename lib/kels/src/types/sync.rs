//! Caching & sync types

use cesr::{Digest, Matter};
use serde::{Deserialize, Serialize};

/// Generate a cryptographic nonce: 32 random bytes hashed with BLAKE3-256, CESR-encoded.
pub fn generate_nonce() -> String {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).unwrap_or_else(|e| unreachable!("getrandom failed: {}", e));
    Digest::blake3_256(&entropy).qb64()
}

/// Request payload for authenticated prefix listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixesRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub since: Option<String>,
    pub limit: Option<usize>,
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
