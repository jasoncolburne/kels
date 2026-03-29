//! Recovery audit records.
//!
//! When a `rec` event resolves divergence, adversary events are archived
//! synchronously during the merge transaction. A single `RecoveryRecord`
//! is written as a permanent audit trail of the recovery.

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Audit record for a completed recovery.
///
/// Written once during the merge transaction after adversary events
/// are archived. Provides a permanent record of what happened.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "kels_recovery")]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRecord {
    #[said]
    pub said: String,
    #[created_at]
    pub created_at: StorageDatetime,
    /// The KEL prefix that was recovered.
    pub kel_prefix: String,
    /// Serial number of the `rec` event.
    pub recovery_serial: u64,
    /// Serial where divergence occurred.
    pub diverged_at: u64,
    /// The `previous` field of the `rec` event, used to identify the adversary branch.
    pub rec_previous: String,
    /// First serial in the submitted recovery batch.
    pub owner_first_serial: u64,
}

/// Links a recovery to an archived adversary event it displaced.
///
/// One entry per archived event, all sharing the same `recovery_said`.
/// Enables tracing from a `RecoveryRecord` to the specific events that
/// were archived during that recovery.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "kels_recovery_events")]
#[serde(rename_all = "camelCase")]
pub struct KelRecoveryEvent {
    #[said]
    pub said: String,
    /// The recovery record this event belongs to.
    pub recovery_said: String,
    /// The SAID of the archived event.
    pub event_said: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_record_create() {
        let record = RecoveryRecord::create(
            "KPrefixExample__________________________________".to_string(),
            3,
            2,
            "KRecPrevious____________________________________".to_string(),
            1,
        )
        .unwrap();

        assert!(!record.said.is_empty());
        assert_eq!(
            record.kel_prefix,
            "KPrefixExample__________________________________"
        );
        assert_eq!(record.recovery_serial, 3);
        assert_eq!(record.diverged_at, 2);
    }

    #[test]
    fn test_recovery_record_json_roundtrip() {
        let record = RecoveryRecord::create(
            "KPrefixExample__________________________________".to_string(),
            3,
            2,
            "KRecPrevious____________________________________".to_string(),
            1,
        )
        .unwrap();

        let json = serde_json::to_string(&record).unwrap();
        let parsed: RecoveryRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, record.said);
        assert_eq!(parsed.kel_prefix, record.kel_prefix);
    }
}
