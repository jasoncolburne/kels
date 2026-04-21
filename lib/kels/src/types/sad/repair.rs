//! SAD Event Log repair types

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Audit event for a completed SAD Event Log repair.
///
/// Each repair gets its own SAID. Multiple repairs to the same chain are
/// distinguished by their `repaired_at` timestamp and unique SAID.
/// The displaced records are linked via `SadEventRepairRecord`.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_event_repairs")]
#[serde(rename_all = "camelCase")]
pub struct SadEventRepair {
    #[said]
    pub said: cesr::Digest256,
    /// The chain prefix that was repaired.
    pub event_prefix: cesr::Digest256,
    /// The version at which divergence occurred.
    pub diverged_at_version: u64,
    /// When the repair was performed.
    #[created_at]
    pub repaired_at: StorageDatetime,
}

/// A page of chain repairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadEventRepairPage {
    pub repairs: Vec<SadEventRepair>,
    pub has_more: bool,
}

/// Links a repair to an archived event it displaced.
///
/// One entry per archived event, all sharing the same `repair_said`.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_event_repair_records")]
#[serde(rename_all = "camelCase")]
pub struct SadEventRepairRecord {
    #[said]
    pub said: cesr::Digest256,
    /// The repair this event belongs to.
    pub repair_said: cesr::Digest256,
    /// The SAID of the archived event.
    pub event_said: cesr::Digest256,
}
