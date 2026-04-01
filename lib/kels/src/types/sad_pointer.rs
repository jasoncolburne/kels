//! SAD (Self-Addressing Data) pointer types for the replicated SADStore.
//!
//! Two layers:
//! - **SAD objects** — content-addressed JSON blobs stored/retrieved by SAID (MinIO).
//! - **Chained records** — versioned chains with deterministic prefix discovery and
//!   KEL ownership. Each pointer references content in the SAD store via `content_said`.
//!
//! Prefix derivation is fully deterministic: given a KEL prefix and kind, anyone can
//! compute the chain prefix offline by constructing the v0 inception pointer (which has
//! no non-deterministic fields) and reading its prefix.

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime, StorageError};

/// A chained, self-addressed pointer in the SADStore.
///
/// The v0 (inception) pointer has `content_said: None` — this makes the prefix
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
pub struct SadPointer {
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
    /// The pointer kind (e.g., `"kels/v1/mlkem-pubkey"`).
    pub kind: String,
    /// SAID of the content object in the SAD store (None for v0 inception).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_said: Option<String>,
}

/// Compute the SAD chain prefix for a given KEL prefix and kind.
///
/// Anyone can call this offline — no server needed. The prefix is derived from
/// the v0 inception pointer content (with said+prefix as placeholders), which
/// contains only deterministic fields.
pub fn compute_sad_prefix(kel_prefix: &str, kind: &str) -> Result<String, StorageError> {
    let pointer = SadPointer::create(kel_prefix.to_string(), kind.to_string(), None)?;
    Ok(pointer.prefix)
}

/// Signature for a SAD pointer, stored separately from the pointer itself.
///
/// Stored in `sad_record_signatures` table (1:1 with `sad_records`).
/// The `establishment_serial` is server-derived, not client-provided.
/// Has its own content-addressed SAID (following the `EventSignature` pattern).
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_record_signatures")]
#[serde(rename_all = "camelCase")]
pub struct SadPointerSignature {
    #[said]
    pub said: String,
    pub pointer_said: String,
    pub signature: String,
    pub establishment_serial: u64,
}

/// A signed SAD pointer as returned by the API.
///
/// Analogous to `SignedKeyEvent` (event + signatures). Includes the
/// server-derived `establishment_serial` so verifiers know which KEL
/// establishment key to check against.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSadPointer {
    pub pointer: SadPointer,
    pub signature: String,
    pub establishment_serial: u64,
}

/// Proof-of-verification token for a SAD pointer chain.
///
/// Cannot be constructed outside this crate — only via `SadPointerVerifier`.
/// Having a `SadPointerVerification` proves the chain was fully verified
/// (structural integrity + signature verification against the KEL).
#[derive(Debug, Clone)]
pub struct SadPointerVerification {
    tip: SadPointer,
    establishment_serial: u64,
}

impl SadPointerVerification {
    /// Create a new verification token. Crate-internal only.
    pub(crate) fn new(tip: SadPointer, establishment_serial: u64) -> Self {
        Self {
            tip,
            establishment_serial,
        }
    }

    /// The latest verified pointer in the chain.
    pub fn current_record(&self) -> &SadPointer {
        &self.tip
    }

    /// The SAID of the content object referenced by the current pointer.
    pub fn current_content_said(&self) -> Option<&str> {
        self.tip.content_said.as_deref()
    }

    /// The KEL establishment serial that signed the tip pointer.
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

    /// The pointer kind.
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
pub enum SadAnnouncement {
    /// A new SAD object was stored (content-addressed blob in MinIO).
    Object {
        /// The SAID of the stored object.
        said: String,
        /// The peer prefix that stored it.
        origin: String,
    },
    /// A SAD pointer chain was updated.
    Pointer {
        /// The chain prefix that was updated.
        chain_prefix: String,
        /// The SAID of the latest chain pointer.
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
pub struct SadPointerPage {
    pub records: Vec<SignedSadPointer>,
    pub has_more: bool,
}

/// Response for listing SAD object SAIDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadObjectListResponse {
    pub saids: Vec<String>,
    pub next_cursor: Option<String>,
}

/// Audit pointer for a completed SAD chain repair.
///
/// Each repair gets its own SAID. Multiple repairs to the same chain are
/// distinguished by their `repaired_at` timestamp and unique SAID.
/// The displaced records are linked via `SadChainRepairRecord`.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_chain_repairs")]
#[serde(rename_all = "camelCase")]
pub struct SadPointerRepair {
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
#[storable(table = "sad_chain_repair_records")]
#[serde(rename_all = "camelCase")]
pub struct SadPointerRepairRecord {
    #[said]
    pub said: String,
    /// The repair this pointer belongs to.
    pub repair_said: String,
    /// The SAID of the archived pointer.
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
        let pointer = SadPointer::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        assert_eq!(pointer.version, 0);
        assert!(pointer.previous.is_none());
        assert!(pointer.content_said.is_none());
        assert!(!pointer.said.is_empty());
        assert!(!pointer.prefix.is_empty());
    }

    #[test]
    fn test_sad_record_chain_increment() {
        let mut pointer = SadPointer::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();

        let v0_said = pointer.said.clone();
        let prefix = pointer.prefix.clone();

        pointer.content_said = Some("Econtent_said_abc".to_string());
        pointer.increment().unwrap();

        assert_eq!(pointer.version, 1);
        assert_eq!(pointer.previous, Some(v0_said));
        assert_eq!(pointer.prefix, prefix);
        assert_eq!(pointer.content_said, Some("Econtent_said_abc".to_string()));
    }

    #[test]
    fn test_sad_gossip_message_serialization() {
        let object_msg = SadAnnouncement::Object {
            said: "Esaid123".to_string(),
            origin: "Eorigin".to_string(),
        };
        let json = serde_json::to_string(&object_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SadAnnouncement::Object { .. }));

        let chain_msg = SadAnnouncement::Pointer {
            chain_prefix: "Eprefix".to_string(),
            said: "Esaid456".to_string(),
            origin: "Eorigin".to_string(),
            repair: false,
        };
        let json = serde_json::to_string(&chain_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            SadAnnouncement::Pointer { repair: false, .. }
        ));

        // Repair messages round-trip correctly
        let repair_msg = SadAnnouncement::Pointer {
            chain_prefix: "Eprefix".to_string(),
            said: "Esaid789".to_string(),
            origin: "Eorigin".to_string(),
            repair: true,
        };
        let json = serde_json::to_string(&repair_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            SadAnnouncement::Pointer { repair: true, .. }
        ));

        // Backwards compatibility: messages without repair field default to false
        // (serde(default) on the field handles this)
        let without_repair = serde_json::to_string(&SadAnnouncement::Pointer {
            chain_prefix: "Ep".to_string(),
            said: "Es".to_string(),
            origin: "Eo".to_string(),
            repair: false,
        })
        .unwrap();
        // Remove the "repair":false field to simulate a legacy message
        let legacy_json = without_repair.replace(",\"repair\":false", "");
        let parsed: SadAnnouncement = serde_json::from_str(&legacy_json).unwrap();
        assert!(matches!(
            parsed,
            SadAnnouncement::Pointer { repair: false, .. }
        ));
    }

    #[test]
    fn test_signed_sad_record_serialization() {
        let pointer = SadPointer::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        let signed = SignedSadPointer {
            pointer,
            signature: "sig123".to_string(),
            establishment_serial: 2,
        };
        let json = serde_json::to_string(&signed).unwrap();
        let parsed: SignedSadPointer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.signature, "sig123");
        assert_eq!(parsed.establishment_serial, 2);
    }

    #[test]
    fn test_sad_record_verify_said() {
        let pointer = SadPointer::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        assert!(pointer.verify_said().is_ok());

        // Tamper with content
        let mut tampered = pointer;
        tampered.kind = "kels/v1/tampered".to_string();
        assert!(tampered.verify_said().is_err());
    }

    #[test]
    fn test_sad_record_verify_prefix() {
        let pointer = SadPointer::create(
            "Ekel123".to_string(),
            "kels/v1/mlkem-pubkey".to_string(),
            None,
        )
        .unwrap();
        assert!(pointer.verify_prefix().is_ok());

        // Tamper with kel_prefix
        let mut tampered = pointer;
        tampered.kel_prefix = "Etampered".to_string();
        tampered.derive_said().unwrap();
        assert!(tampered.verify_prefix().is_err());
    }
}
