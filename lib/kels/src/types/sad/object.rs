//! SAD object index types

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Index entry tracking a SAD object stored in object store.
///
/// #167: the pre-reshape single `custody` SAID column is
/// replaced by denormalized columns sourced from the parent SAD's inline
/// `custody.read` and `availability.{nodes,ttl,once}` fields. All four
/// participate in the entry's SAID computation, so a verifier can
/// reconstruct the entry from the parent SAD's bytes (which are
/// content-addressable in object store) and confirm the index row is
/// faithful — the DB stays untrusted, the source of truth stays the
/// SAID-verified parent SAD.
///
/// `custody.write` is deliberately not denormalized: write-policy
/// enforcement happens at POST time and doesn't need a fetch-path lookup.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_objects")]
#[serde(rename_all = "camelCase")]
pub struct SadObjectEntry {
    #[said]
    pub said: cesr::Digest256,
    pub sad_said: cesr::Digest256,
    #[created_at]
    pub created_at: StorageDatetime,
    /// `custody.read` — IEL prefix gating user-facing reads.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub custody_read: Option<cesr::Digest256>,
    /// `availability.nodes` — NodeSet SAD reference.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub availability_nodes: Option<cesr::Digest256>,
    /// `availability.ttl` — lifetime in seconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub availability_ttl: Option<u64>,
    /// `availability.once` — read-once semantics.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub availability_once: Option<bool>,
}

/// Response for listing SAD object SAIDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadObjectListResponse {
    pub saids: Vec<cesr::Digest256>,
    pub next_cursor: Option<cesr::Digest256>,
}
