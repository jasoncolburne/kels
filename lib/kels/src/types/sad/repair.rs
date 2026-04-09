//! SAD pointer chain repair types

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Audit pointer for a completed SAD chain repair.
///
/// Each repair gets its own SAID. Multiple repairs to the same chain are
/// distinguished by their `repaired_at` timestamp and unique SAID.
/// The displaced records are linked via `SadChainRepairRecord`.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_pointer_repairs")]
#[serde(rename_all = "camelCase")]
pub struct SadPointerRepair {
    #[said]
    pub said: cesr::Digest,
    /// The chain prefix that was repaired.
    pub pointer_prefix: cesr::Digest,
    /// The version at which divergence occurred.
    pub diverged_at_version: u64,
    /// When the repair was performed.
    #[created_at]
    pub repaired_at: StorageDatetime,
}

/// A page of chain repairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadPointerRepairPage {
    pub repairs: Vec<SadPointerRepair>,
    pub has_more: bool,
}

/// Links a repair to an archived pointer it displaced.
///
/// One entry per archived pointer, all sharing the same `repair_said`.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_pointer_repair_records")]
#[serde(rename_all = "camelCase")]
pub struct SadPointerRepairRecord {
    #[said]
    pub said: cesr::Digest,
    /// The repair this pointer belongs to.
    pub repair_said: cesr::Digest,
    /// The SAID of the archived pointer.
    pub pointer_said: cesr::Digest,
}
