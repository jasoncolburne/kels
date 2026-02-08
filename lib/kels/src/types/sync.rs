//! Caching & sync types

use super::events::SignedKeyEvent;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server-caching", derive(cacheable::Cacheable))]
#[cfg_attr(feature = "server-caching", cache(prefix = "kels:kel", ttl = 3600))]
#[serde(rename_all = "camelCase")]
pub struct CachedKel {
    #[cfg_attr(feature = "server-caching", cache_key(primary))]
    pub prefix: String,
    pub events: Vec<SignedKeyEvent>,
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
