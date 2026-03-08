//! Caching & sync types

use cesr::{Digest, Matter};
use serde::{Deserialize, Serialize};

/// Generate a cryptographic nonce: 32 random bytes hashed with BLAKE3-256, CESR-encoded.
pub fn generate_nonce() -> String {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).unwrap_or_else(|e| unreachable!("getrandom failed: {}", e));
    Digest::blake3_256(&entropy).qb64()
}

/// Hash sorted tip SAIDs into a single deterministic CESR-encoded Blake3 digest.
///
/// Used to represent the state of a divergent KEL where multiple branch tips exist.
/// The SAIDs are sorted alphabetically, concatenated, and Blake3-hashed.
pub fn hash_tip_saids(saids: &[&str]) -> String {
    let mut sorted: Vec<&str> = saids.to_vec();
    sorted.sort();
    let concatenated = sorted.join("");
    Digest::blake3_256(concatenated.as_bytes()).qb64()
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
