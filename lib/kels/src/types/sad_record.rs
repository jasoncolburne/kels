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
use verifiable_storage::{Chained, SelfAddressed, StorageError};

use crate::KelsError;

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

/// A signed SAD record for transmission over the wire.
///
/// The `establishment_serial` is NOT included — the server determines it by
/// finding the most recent establishment event in the KEL and verifying the
/// signature against that key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSadRecord {
    pub record: SadRecord,
    /// Signature over the record's SAID, using the current KEL signing key.
    pub signature: String,
}

/// A chain of SAD records for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadRecordChain {
    pub prefix: String,
    pub records: Vec<SadRecord>,
}

impl SadRecordChain {
    /// Verify structural integrity of the chain.
    ///
    /// Checks:
    /// - SAID integrity per record
    /// - Chain linkage (previous → said)
    /// - Version monotonicity (version == index)
    /// - Consistent `kel_prefix` and `kind` across all records
    /// - First record has no previous, subsequent records do
    /// - Prefix matches across all records
    pub fn verify_records(&self) -> Result<(), KelsError> {
        if self.records.is_empty() {
            return Err(KelsError::VerificationFailed(
                "Empty SAD record chain".into(),
            ));
        }

        let expected_kel_prefix = &self.records[0].kel_prefix;
        let expected_kind = &self.records[0].kind;
        let mut last_said: Option<String> = None;

        for (i, record) in self.records.iter().enumerate() {
            record.verify()?;

            if record.prefix != self.prefix {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} prefix {} doesn't match chain prefix {}",
                    record.said, record.prefix, self.prefix
                )));
            }

            if record.kel_prefix != *expected_kel_prefix {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} kel_prefix {} doesn't match chain kel_prefix {}",
                    record.said, record.kel_prefix, expected_kel_prefix
                )));
            }

            if record.kind != *expected_kind {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} kind {} doesn't match chain kind {}",
                    record.said, record.kind, expected_kind
                )));
            }

            if let Some(said) = &last_said {
                if record.previous.as_deref() != Some(said.as_str()) {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD record {} previous doesn't match {}",
                        record.said, said
                    )));
                }
            } else if record.previous.is_some() {
                return Err(KelsError::VerificationFailed(format!(
                    "First SAD record {} has unexpected previous",
                    record.said
                )));
            }

            if i as u64 != record.version {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD record {} has incorrect version {}",
                    record.said, record.version
                )));
            }

            last_said = Some(record.said.clone());
        }

        Ok(())
    }

    /// Get the latest (tip) record in the chain.
    pub fn tip(&self) -> Option<&SadRecord> {
        self.records.last()
    }
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
    #[allow(dead_code)]
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
    },
}

/// A page of SAD records returned by the chain API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadRecordPage {
    pub records: Vec<SadRecord>,
    pub has_more: bool,
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
    fn test_sad_record_chain_verify_valid() {
        let v0 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1 = v0.clone();
        v1.content_said = Some("Econtent1".to_string());
        v1.increment().unwrap();

        let chain = SadRecordChain {
            prefix: v0.prefix.clone(),
            records: vec![v0, v1],
        };
        assert!(chain.verify_records().is_ok());
    }

    #[test]
    fn test_sad_record_chain_verify_empty_fails() {
        let chain = SadRecordChain {
            prefix: "Etest".to_string(),
            records: vec![],
        };
        assert!(chain.verify_records().is_err());
    }

    #[test]
    fn test_sad_record_chain_verify_broken_linkage_fails() {
        let v0 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        // Create v1 without proper increment (broken linkage)
        let mut v1 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        // Manually set version to simulate broken chain
        v1.version = 1;
        v1.previous = Some("Ewrong_said".to_string());
        v1.derive_said().unwrap();

        let chain = SadRecordChain {
            prefix: v0.prefix.clone(),
            records: vec![v0, v1],
        };
        let err = chain.verify_records().unwrap_err();
        assert!(
            err.to_string().contains("previous doesn't match"),
            "Expected chain linkage error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_record_chain_verify_inconsistent_kind_fails() {
        let v0 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1 = v0.clone();
        v1.kind = "kels/v1/other-kind".to_string();
        v1.increment().unwrap();

        let chain = SadRecordChain {
            prefix: v0.prefix.clone(),
            records: vec![v0, v1],
        };
        let err = chain.verify_records().unwrap_err();
        assert!(
            err.to_string().contains("kind"),
            "Expected kind mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_sad_record_chain_verify_wrong_version_fails() {
        let v0 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1 = v0.clone();
        v1.content_said = Some("Econtent1".to_string());
        v1.increment().unwrap();
        // Tamper with version
        v1.version = 5;
        v1.derive_said().unwrap();

        let chain = SadRecordChain {
            prefix: v0.prefix.clone(),
            records: vec![v0, v1],
        };
        let err = chain.verify_records().unwrap_err();
        assert!(
            err.to_string().contains("incorrect version"),
            "Expected version error, got: {}",
            err
        );
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
        };
        let json = serde_json::to_string(&chain_msg).unwrap();
        let parsed: SadGossipMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SadGossipMessage::Chain { .. }));
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
        };
        let json = serde_json::to_string(&signed).unwrap();
        let parsed: SignedSadRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.signature, "sig123");
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

    #[test]
    fn test_sad_record_chain_tip() {
        let v0 = SadRecord::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let mut v1 = v0.clone();
        v1.content_said = Some("Econtent1".to_string());
        v1.increment().unwrap();

        let chain = SadRecordChain {
            prefix: v0.prefix.clone(),
            records: vec![v0, v1.clone()],
        };
        assert_eq!(chain.tip().unwrap().said, v1.said);
    }
}
