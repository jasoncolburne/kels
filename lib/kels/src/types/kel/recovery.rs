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
    pub said: cesr::Digest,
    #[created_at]
    pub created_at: StorageDatetime,
    /// The KEL prefix that was recovered.
    pub kel_prefix: cesr::Digest,
    /// Serial number of the `rec` event.
    pub recovery_serial: u64,
    /// Serial where divergence occurred.
    pub diverged_at: u64,
    /// The `previous` field of the `rec` event, used to identify the adversary branch.
    pub rec_previous: cesr::Digest,
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
    pub said: cesr::Digest,
    /// The recovery record this event belongs to.
    pub recovery_said: cesr::Digest,
    /// The SAID of the archived event.
    pub event_said: cesr::Digest,
}

/// A page of recovery records.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRecordPage {
    pub records: Vec<RecoveryRecord>,
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_record_create() {
        let record = RecoveryRecord::create(
            cesr::Digest::blake3_256(b"prefix_example"),
            3,
            2,
            cesr::Digest::blake3_256(b"rec_previous"),
            1,
        )
        .unwrap();

        assert_eq!(record.said.to_string().len(), 44);
        assert_eq!(
            record.kel_prefix,
            cesr::Digest::blake3_256(b"prefix_example")
        );
        assert_eq!(record.recovery_serial, 3);
        assert_eq!(record.diverged_at, 2);
    }

    #[test]
    fn test_recovery_record_json_roundtrip() {
        let record = RecoveryRecord::create(
            cesr::Digest::blake3_256(b"prefix_example"),
            3,
            2,
            cesr::Digest::blake3_256(b"rec_previous"),
            1,
        )
        .unwrap();

        let json = serde_json::to_string(&record).unwrap();
        let parsed: RecoveryRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, record.said);
        assert_eq!(parsed.kel_prefix, record.kel_prefix);
    }
}
