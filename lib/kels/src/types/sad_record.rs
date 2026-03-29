//! SAD (Self-Addressing Data) record types for the replicated SADStore.
//!
//! Two layers:
//! - **SAD objects** — content-addressed JSON blobs stored/retrieved by SAID (MinIO).
//! - **Chained records** — versioned chains with deterministic prefix discovery and
//!   KEL ownership. Each record references content in the SAD store via `content_said`.
//!
//! Prefix derivation is fully deterministic: given a KEL prefix and kind, anyone can
//! compute the chain prefix offline by constructing the v0 inception record (which has
//! no non-deterministic fields) and reading its prefix.

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime, StorageError};

/// A chained, self-addressed record in the SADStore.
///
/// The v0 (inception) record has `content_said: None` — this makes the prefix
/// fully deterministic from `kel_prefix` + `kind` alone. Content is added in v1+.
///
/// No `created_at` field — intentionally omitted so inception records are fully
/// deterministic for prefix computation.
///
/// Signature and establishment_serial are stored alongside in the DB but are NOT
/// part of this struct — they don't affect SAID computation.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_records")]
#[serde(rename_all = "camelCase")]
pub struct SadRecord {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    /// The owning KEL's prefix.
    pub kel_prefix: String,
    /// The record kind (e.g., `"kels/v1/mlkem-pubkey"`).
    pub kind: String,
    /// SAID of the content object in the SAD store (None for v0 inception).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_said: Option<String>,
}

/// Compute the SAD chain prefix for a given KEL prefix and kind.
///
/// Anyone can call this offline — no server needed. The prefix is derived from
/// the v0 inception record content (with said+prefix as placeholders), which
/// contains only deterministic fields.
pub fn compute_sad_prefix(kel_prefix: &str, kind: &str) -> Result<String, StorageError> {
    let record = SadRecord::create(kel_prefix.to_string(), kind.to_string(), None)?;
    Ok(record.prefix)
}

/// Signature for a SAD record, stored separately from the record itself.
///
/// Stored in `sad_record_signatures` table (1:1 with `sad_records`).
/// The `establishment_serial` is server-derived, not client-provided.
/// Has its own content-addressed SAID (following the `EventSignature` pattern).
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_record_signatures")]
#[serde(rename_all = "camelCase")]
pub struct SadRecordSignature {
    #[said]
    pub said: String,
    pub record_said: String,
    pub signature: String,
    pub establishment_serial: u64,
}

/// A SAD record submission — record + signature, no establishment serial.
///
/// The `establishment_serial` is NOT included — the server determines it by
/// finding the most recent establishment event in the KEL and verifying the
/// signature against that key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadRecordSubmission {
    pub record: SadRecord,
    /// Signature over the record's SAID, using the current KEL signing key.
    pub signature: String,
}

/// A signed SAD record as returned by the API.
///
/// Analogous to `SignedKeyEvent` (event + signatures). Includes the
/// server-derived `establishment_serial` so verifiers know which KEL
/// establishment key to check against.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSadRecord {
    pub record: SadRecord,
    pub signature: String,
    pub establishment_serial: u64,
}

/// Proof-of-verification token for a SAD record chain.
///
/// Cannot be constructed outside this crate — only via `SadRecordVerifier`.
/// Having a `SadRecordVerification` proves the chain was fully verified
/// (structural integrity + signature verification against the KEL).
#[derive(Debug, Clone)]
pub struct SadRecordVerification {
    tip: SadRecord,
    establishment_serial: u64,
}

impl SadRecordVerification {
    /// Create a new verification token. Crate-internal only.
    pub(crate) fn new(tip: SadRecord, establishment_serial: u64) -> Self {
        Self {
            tip,
            establishment_serial,
        }
    }

    /// The latest verified record in the chain.
    pub fn current_record(&self) -> &SadRecord {
        &self.tip
    }

    /// The SAID of the content object referenced by the current record.
    pub fn current_content_said(&self) -> Option<&str> {
        self.tip.content_said.as_deref()
    }

    /// The KEL establishment serial that signed the tip record.
    pub fn establishment_serial(&self) -> u64 {
        self.establishment_serial
    }

    /// The chain prefix.
    pub fn prefix(&self) -> &str {
        &self.tip.prefix
    }

    /// The owning KEL prefix.
    pub fn kel_prefix(&self) -> &str {
        &self.tip.kel_prefix
    }

    /// The record kind.
    pub fn kind(&self) -> &str {
        &self.tip.kind
    }
}

/// Gossip message types for SAD replication.
///
/// Broadcast on topic `kels/sad/v1`. Tagged enum allows routing both
/// raw SAD object announcements and chain update announcements on a single topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SadGossipMessage {
    /// A new SAD object was stored (content-addressed blob in MinIO).
    Object {
        /// The SAID of the stored object.
        said: String,
        /// The peer prefix that stored it.
        origin: String,
    },
    /// A SAD record chain was updated.
    Chain {
        /// The chain prefix that was updated.
        chain_prefix: String,
        /// The SAID of the latest chain record.
        said: String,
        /// The peer prefix that stored it.
        origin: String,
        /// Whether this update is a repair of a previously divergent chain.
        /// When true, the receiving node should use `?repair=true` to replace
        /// its local divergent chain.
        #[serde(default)]
        repair: bool,
    },
}

/// Index entry tracking a SAD object stored in MinIO.
///
/// Has its own content-addressed SAID. The `sad_said` field is the
/// SAID of the actual object in MinIO (foreign key to object storage).
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_objects")]
#[serde(rename_all = "camelCase")]
pub struct SadObjectEntry {
    #[said]
    pub said: String,
    pub sad_said: String,
}

/// A page of stored SAD records returned by the chain API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadRecordPage {
    pub records: Vec<SignedSadRecord>,
    pub has_more: bool,
}

/// Response for listing SAD object SAIDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadObjectListResponse {
    pub saids: Vec<String>,
    pub next_cursor: Option<String>,
}

/// Audit record for a completed SAD chain repair.
///
/// Each repair gets its own SAID. Multiple repairs to the same chain are
/// distinguished by their `repaired_at` timestamp and unique SAID.
/// The displaced records are linked via `SadChainRepairRecord`.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_chain_repairs")]
#[serde(rename_all = "camelCase")]
pub struct SadChainRepair {
    #[said]
    pub said: String,
    /// The chain prefix that was repaired.
    pub record_prefix: String,
    /// The version at which divergence occurred.
    pub diverged_at_version: u64,
    /// When the repair was performed.
    #[created_at]
    pub repaired_at: StorageDatetime,
}

/// Links a repair to an archived record it displaced.
///
/// One entry per archived record, all sharing the same `repair_said`.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_chain_repair_records")]
#[serde(rename_all = "camelCase")]
pub struct SadChainRepairRecord {
    #[said]
    pub said: String,
    /// The repair this record belongs to.
    pub repair_said: String,
    /// The SAID of the archived record.
    pub record_said: String,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use verifiable_storage::{Chained, SelfAddressed};

    use super::*;

    #[test]
    fn test_compute_sad_prefix_deterministic() {
        let prefix1 = compute_sad_prefix("Ekel123", "kels/v1/mlkem-pubkey").unwrap();
        let prefix2 = compute_sad_prefix("Ekel123", "kels/v1/mlkem-pubkey").unwrap();
        assert_eq!(prefix1, prefix2);
    }

    #[test]
    fn test_compute_sad_prefix_different_inputs() {
        let prefix1 = compute_sad_prefix("Ekel123", "kels/v1/mlkem-pubkey").unwrap();
        let prefix2 = compute_sad_prefix("Ekel456", "kels/v1/mlkem-pubkey").unwrap();
        assert_ne!(prefix1, prefix2);

        let prefix3 = compute_sad_prefix("Ekel123", "kels/v1/other-kind").unwrap();
        assert_ne!(prefix1, prefix3);
    }

    #[test]
    fn test_sad_record_inception_no_content() {
        let record = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        assert_eq!(record.version, 0);
        assert!(record.previous.is_none());
        assert!(record.content_said.is_none());
        assert!(!record.said.is_empty());
        assert!(!record.prefix.is_empty());
    }

    #[test]
    fn test_sad_record_chain_increment() {
        let mut record = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let v0_said = record.said.clone();
        let prefix = record.prefix.clone();

        record.content_said = Some("Econtent_said_abc".to_string());
        record.increment().unwrap();

        assert_eq!(record.version, 1);
        assert_eq!(record.previous, Some(v0_said));
        assert_eq!(record.prefix, prefix);
        assert_eq!(record.content_said, Some("Econtent_said_abc".to_string()));
    }

    #[test]
    fn test_sad_gossip_message_serialization() {
        let object_msg = SadGossipMessage::Object {
            said: "Esaid123".to_string(),
            origin: "Eorigin".to_string(),
        };
        let json = serde_json::to_string(&object_msg).unwrap();
        let parsed: SadGossipMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SadGossipMessage::Object { .. }));

        let chain_msg = SadGossipMessage::Chain {
            chain_prefix: "Eprefix".to_string(),
            said: "Esaid456".to_string(),
            origin: "Eorigin".to_string(),
            repair: false,
        };
        let json = serde_json::to_string(&chain_msg).unwrap();
        let parsed: SadGossipMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            SadGossipMessage::Chain { repair: false, .. }
        ));

        // Repair messages round-trip correctly
        let repair_msg = SadGossipMessage::Chain {
            chain_prefix: "Eprefix".to_string(),
            said: "Esaid789".to_string(),
            origin: "Eorigin".to_string(),
            repair: true,
        };
        let json = serde_json::to_string(&repair_msg).unwrap();
        let parsed: SadGossipMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            SadGossipMessage::Chain { repair: true, .. }
        ));

        // Backwards compatibility: messages without repair field default to false
        // (serde(default) on the field handles this)
        let without_repair = serde_json::to_string(&SadGossipMessage::Chain {
            chain_prefix: "Ep".to_string(),
            said: "Es".to_string(),
            origin: "Eo".to_string(),
            repair: false,
        })
        .unwrap();
        // Remove the "repair":false field to simulate a legacy message
        let legacy_json = without_repair.replace(",\"repair\":false", "");
        let parsed: SadGossipMessage = serde_json::from_str(&legacy_json).unwrap();
        assert!(matches!(
            parsed,
            SadGossipMessage::Chain { repair: false, .. }
        ));
    }

    #[test]
    fn test_sad_record_submission_serialization() {
        let record = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let submission = SadRecordSubmission {
            record,
            signature: "sig123".to_string(),
        };
        let json = serde_json::to_string(&submission).unwrap();
        let parsed: SadRecordSubmission = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.signature, "sig123");
    }

    #[test]
    fn test_signed_sad_record_serialization() {
        let record = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let signed = SignedSadRecord {
            record,
            signature: "sig123".to_string(),
            establishment_serial: 2,
        };
        let json = serde_json::to_string(&signed).unwrap();
        let parsed: SignedSadRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.signature, "sig123");
        assert_eq!(parsed.establishment_serial, 2);
    }

    #[test]
    fn test_sad_record_verify_said() {
        let record = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        assert!(record.verify_said().is_ok());

        // Tamper with content
        let mut tampered = record;
        tampered.kind = "kels/v1/tampered".to_string();
        assert!(tampered.verify_said().is_err());
    }

    #[test]
    fn test_sad_record_verify_prefix() {
        let record = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        assert!(record.verify_prefix().is_ok());

        // Tamper with kel_prefix
        let mut tampered = record;
        tampered.kel_prefix = "Etampered".to_string();
        tampered.derive_said().unwrap();
        assert!(tampered.verify_prefix().is_err());
    }
}
