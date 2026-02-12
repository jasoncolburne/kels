//! Caching & sync types

use serde::{Deserialize, Serialize};

/// Request payload for authenticated prefix listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixesRequest {
    pub timestamp: i64,
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
