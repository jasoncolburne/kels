//! Recovery state tracking for async adversary archival.
//!
//! When a `rec` event resolves divergence, adversary events are archived
//! asynchronously by a background task. A `RecoveryRecord` chain tracks
//! each recovery's progress — one record per state transition, forming
//! an immutable audit trail.

use std::fmt;

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// State machine for async recovery archival.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryState {
    /// Recovery accepted, awaiting archival.
    Pending,
    /// Background task is actively archiving adversary events.
    Archiving,
    /// Archival complete, performing final cleanup (cache invalidation, etc.).
    Cleanup,
    /// Terminal state. Recovery is complete. Serves as audit trail.
    Recovered,
}

impl fmt::Display for RecoveryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryState::Pending => write!(f, "pending"),
            RecoveryState::Archiving => write!(f, "archiving"),
            RecoveryState::Cleanup => write!(f, "cleanup"),
            RecoveryState::Recovered => write!(f, "recovered"),
        }
    }
}

impl std::str::FromStr for RecoveryState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(RecoveryState::Pending),
            "archiving" => Ok(RecoveryState::Archiving),
            "cleanup" => Ok(RecoveryState::Cleanup),
            "recovered" => Ok(RecoveryState::Recovered),
            other => Err(format!("unknown recovery state: {other}")),
        }
    }
}

/// Chained record tracking recovery progress for a single KEL prefix.
///
/// Each state transition creates a new record via `increment()`, forming
/// an immutable audit trail. Records are never deleted.
///
/// The `prefix` field is the stable chain identifier (derived at inception).
/// The `kel_prefix` field is the KEL being recovered.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "kels_recovery")]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRecord {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    #[created_at]
    pub created_at: StorageDatetime,
    /// The KEL prefix being recovered.
    pub kel_prefix: String,
    /// Serial number of the `rec` event. Events at `recovery_serial + 1`
    /// (the `rot`) are hidden until recovery completes.
    pub recovery_serial: u64,
    /// Serial where divergence occurred.
    pub diverged_at: u64,
    /// The `previous` field of the `rec` event, used to identify the adversary branch.
    pub rec_previous: String,
    /// First serial in the submitted recovery batch. Distinguishes
    /// "owner has events at divergence serial" vs "all events are adversary".
    pub owner_first_serial: u64,
    /// Current state in the recovery state machine.
    pub state: RecoveryState,
    /// Archival progress: next serial to process (backward from tail).
    pub cursor_serial: u64,
    /// SAID of the last adversary event processed, for chain-following.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adversary_tip_said: Option<String>,
}

#[cfg(test)]
mod tests {
    use verifiable_storage::Chained;

    use super::*;

    #[test]
    fn test_recovery_record_create() {
        let record = RecoveryRecord::create(
            "KPrefixExample__________________________________".to_string(),
            3,
            2,
            "KRecPrevious____________________________________".to_string(),
            1,
            RecoveryState::Pending,
            0,
            None,
        )
        .unwrap();

        assert!(!record.said.is_empty());
        assert!(!record.prefix.is_empty());
        assert!(record.previous.is_none());
        assert_eq!(record.version, 0);
        assert_eq!(
            record.kel_prefix,
            "KPrefixExample__________________________________"
        );
        assert_eq!(record.recovery_serial, 3);
        assert_eq!(record.diverged_at, 2);
        assert_eq!(record.state, RecoveryState::Pending);
        assert_eq!(record.cursor_serial, 0);
        assert!(record.adversary_tip_said.is_none());
    }

    #[test]
    fn test_recovery_record_state_transition() {
        let record = RecoveryRecord::create(
            "KPrefixExample__________________________________".to_string(),
            3,
            2,
            "KRecPrevious____________________________________".to_string(),
            1,
            RecoveryState::Pending,
            0,
            None,
        )
        .unwrap();

        let original_said = record.said.clone();
        let original_prefix = record.prefix.clone();

        let mut next = record.clone();
        next.state = RecoveryState::Archiving;
        next.increment().unwrap();

        assert_ne!(next.said, original_said);
        assert_eq!(next.prefix, original_prefix);
        assert_eq!(next.previous, Some(original_said));
        assert_eq!(next.version, 1);
        assert_eq!(next.state, RecoveryState::Archiving);
    }

    #[test]
    fn test_recovery_record_full_lifecycle() {
        let mut record = RecoveryRecord::create(
            "KPrefixExample__________________________________".to_string(),
            5,
            3,
            "KRecPrevious____________________________________".to_string(),
            2,
            RecoveryState::Pending,
            0,
            None,
        )
        .unwrap();

        // pending → archiving
        record.state = RecoveryState::Archiving;
        record.increment().unwrap();
        assert_eq!(record.version, 1);

        // archiving (progress)
        record.cursor_serial = 4;
        record.adversary_tip_said =
            Some("KAdvSaid________________________________________".to_string());
        record.increment().unwrap();
        assert_eq!(record.version, 2);

        // archiving → cleanup
        record.state = RecoveryState::Cleanup;
        record.increment().unwrap();
        assert_eq!(record.version, 3);

        // cleanup → recovered
        record.state = RecoveryState::Recovered;
        record.increment().unwrap();
        assert_eq!(record.version, 4);
        assert_eq!(record.state, RecoveryState::Recovered);
    }

    #[test]
    fn test_recovery_state_display_roundtrip() {
        for state in [
            RecoveryState::Pending,
            RecoveryState::Archiving,
            RecoveryState::Cleanup,
            RecoveryState::Recovered,
        ] {
            let s = state.to_string();
            let parsed: RecoveryState = s.parse().unwrap();
            assert_eq!(parsed, state);
        }
    }

    #[test]
    fn test_recovery_record_json_roundtrip() {
        let record = RecoveryRecord::create(
            "KPrefixExample__________________________________".to_string(),
            3,
            2,
            "KRecPrevious____________________________________".to_string(),
            1,
            RecoveryState::Pending,
            0,
            None,
        )
        .unwrap();

        let json = serde_json::to_string(&record).unwrap();
        let parsed: RecoveryRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, record.said);
        assert_eq!(parsed.prefix, record.prefix);
        assert_eq!(parsed.kel_prefix, record.kel_prefix);
        assert_eq!(parsed.state, record.state);
    }

    #[test]
    fn test_recovery_state_parse_invalid() {
        assert!("invalid".parse::<RecoveryState>().is_err());
    }
}
