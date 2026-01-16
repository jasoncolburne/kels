//! KELS types for API requests and responses

use crate::error::KelsError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use verifiable_storage::{SelfAddressed, StorageDatetime, Versioned};

/// Key event types in the KEL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    /// Inception - creates a new KEL
    Icp,
    /// Delegated inception - creates a delegated KEL
    Dip,
    /// Rotation - rotates signing key only
    Rot,
    /// Interaction - anchors a SAID
    Ixn,
    /// Recovery - dual-sig recovery from divergence
    Rec,
    /// Recovery rotation - proactive dual-key rotation
    Ror,
    /// Decommission - voluntary KEL termination
    Dec,
    /// Contest - adversary revealed recovery key, KEL frozen
    Cnt,
}

impl EventKind {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Icp => "icp",
            Self::Dip => "dip",
            Self::Rot => "rot",
            Self::Ixn => "ixn",
            Self::Rec => "rec",
            Self::Ror => "ror",
            Self::Dec => "dec",
            Self::Cnt => "cnt",
        }
    }

    /// Returns true if this is an inception event (icp or dip)
    pub fn is_inception(&self) -> bool {
        matches!(self, Self::Icp | Self::Dip)
    }

    /// Returns true if this is an establishment event (has public key)
    pub fn is_establishment(&self) -> bool {
        !matches!(self, Self::Ixn)
    }

    /// Returns true if this event reveals a recovery key
    pub fn reveals_recovery_key(&self) -> bool {
        matches!(self, Self::Rec | Self::Ror | Self::Dec | Self::Cnt)
    }

    /// Returns true if this event requires dual signatures
    pub fn requires_dual_signature(&self) -> bool {
        self.reveals_recovery_key()
    }

    /// Returns true if this event decommissions the KEL
    pub fn decommissions(&self) -> bool {
        matches!(self, Self::Dec | Self::Cnt)
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for EventKind {
    type Err = KelsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "icp" => Ok(Self::Icp),
            "dip" => Ok(Self::Dip),
            "rot" => Ok(Self::Rot),
            "ixn" => Ok(Self::Ixn),
            "rec" => Ok(Self::Rec),
            "ror" => Ok(Self::Ror),
            "dec" => Ok(Self::Dec),
            "cnt" => Ok(Self::Cnt),
            _ => Err(KelsError::InvalidKeyEvent(format!(
                "Unknown event kind: {}",
                s
            ))),
        }
    }
}

/// Result of merging events into a KEL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KelMergeResult {
    /// Events accepted (no divergence, or idempotent re-submission)
    Verified,
    /// Recovery succeeded - KEL continues or decommissioned by choice
    Recovered,
    /// Divergence with no establishments - user can recover with rec
    Recoverable,
    /// Adversary revealed recovery key - user SHOULD submit cnt to contest
    Contestable,
    /// Key compromise - both parties revealed recovery keys, KEL frozen
    Contested,
    /// KEL is already divergent - only rec/cnt events allowed
    Frozen,
    /// KEL has rec/cnt at this version - cannot introduce divergence
    RecoveryProtected,
}

/// Outcome of a recovery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// Normal recovery - KEL continues with new keys
    Recovered,
    /// Adversary had recovery key - KEL frozen via contest event
    Contested,
}

/// Error response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
}

/// Key Event with SAID pattern.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "kels_key_events")]
#[serde(rename_all = "camelCase")]
pub struct KeyEvent {
    /// Self-Addressing IDentifier
    #[said]
    pub said: String,

    /// Record lineage (groups all versions)
    #[prefix]
    pub prefix: String,

    /// Previous version's SAID
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,

    /// Version counter
    #[version]
    pub version: u64,

    /// Public key if this is an establishment event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// Rotation hash (digest of next signing key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_hash: Option<String>,

    /// Recovery key - revealed only in rec/ror/dec/cnt events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<String>,

    /// Recovery hash (digest of next recovery key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_hash: Option<String>,

    /// Event type
    pub kind: EventKind,

    /// Anchor SAID for domains and records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,

    /// Delegator's KEL prefix (only for dip events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegating_prefix: Option<String>,

    /// When this event was created
    #[created_at]
    pub created_at: StorageDatetime,
}

impl KeyEvent {
    pub fn create_inception(
        public_key: String,
        rotation_hash: String,
        recovery_hash: String,
    ) -> Result<Self, KelsError> {
        let mut icp = Self {
            said: String::new(),
            prefix: String::new(),
            previous: None,
            version: 0,
            public_key: Some(public_key),
            rotation_hash: Some(rotation_hash),
            recovery_key: None,
            recovery_hash: Some(recovery_hash),
            kind: EventKind::Icp,
            anchor: None,
            delegating_prefix: None,
            created_at: StorageDatetime::now(),
        };
        icp.derive_prefix()?;
        Ok(icp)
    }

    pub fn create_delegated_inception(
        public_key: String,
        rotation_hash: String,
        recovery_hash: String,
        delegating_prefix: String,
    ) -> Result<Self, KelsError> {
        let mut dip = Self {
            said: String::new(),
            prefix: String::new(),
            previous: None,
            version: 0,
            public_key: Some(public_key),
            rotation_hash: Some(rotation_hash),
            recovery_key: None,
            recovery_hash: Some(recovery_hash),
            kind: EventKind::Dip,
            anchor: None,
            delegating_prefix: Some(delegating_prefix),
            created_at: StorageDatetime::now(),
        };
        dip.derive_prefix()?;
        Ok(dip)
    }

    /// Create a new rotation event from the previous event.
    pub fn create_rotation(
        previous_event: &Self,
        public_key: String,
        rotation_hash: Option<String>,
    ) -> Result<Self, KelsError> {
        let mut event = previous_event.clone();
        event.kind = EventKind::Rot;
        event.public_key = Some(public_key);
        event.rotation_hash = rotation_hash;
        event.recovery_key = None;
        event.recovery_hash = None;
        event.anchor = None;
        event.delegating_prefix = None;
        event.increment()?;
        Ok(event)
    }

    /// Create a new interaction event from the previous event.
    pub fn create_interaction(previous_event: &Self, anchor: String) -> Result<Self, KelsError> {
        let mut event = previous_event.clone();
        event.kind = EventKind::Ixn;
        event.public_key = None;
        event.rotation_hash = None;
        event.recovery_key = None;
        event.recovery_hash = None;
        event.anchor = Some(anchor);
        event.delegating_prefix = None;
        event.increment()?;
        Ok(event)
    }

    /// Create a new recovery event from the previous event.
    pub fn create_recovery(
        previous_event: &Self,
        public_key: String,
        rotation_hash: String,
        recovery_key: String,
        recovery_hash: String,
    ) -> Result<Self, KelsError> {
        let mut event = previous_event.clone();
        event.kind = EventKind::Rec;
        event.public_key = Some(public_key);
        event.rotation_hash = Some(rotation_hash);
        event.recovery_key = Some(recovery_key);
        event.recovery_hash = Some(recovery_hash);
        event.anchor = None;
        event.delegating_prefix = None;
        event.increment()?;
        Ok(event)
    }

    /// Create a new recovery rotation event.
    pub fn create_recovery_rotation(
        previous_event: &Self,
        public_key: String,
        rotation_hash: String,
        recovery_key: String,
        recovery_hash: String,
    ) -> Result<Self, KelsError> {
        let mut event = previous_event.clone();
        event.kind = EventKind::Ror;
        event.public_key = Some(public_key);
        event.rotation_hash = Some(rotation_hash);
        event.recovery_key = Some(recovery_key);
        event.recovery_hash = Some(recovery_hash);
        event.anchor = None;
        event.delegating_prefix = None;
        event.increment()?;
        Ok(event)
    }

    /// Create a new decommission event.
    pub fn create_decommission(
        previous_event: &Self,
        public_key: String,
        recovery_key: String,
    ) -> Result<Self, KelsError> {
        let mut event = previous_event.clone();
        event.kind = EventKind::Dec;
        event.public_key = Some(public_key);
        event.rotation_hash = None;
        event.recovery_key = Some(recovery_key);
        event.recovery_hash = None;
        event.anchor = None;
        event.delegating_prefix = None;
        event.increment()?;
        Ok(event)
    }

    /// Create a new contest event.
    pub fn create_contest(
        previous_event: &Self,
        public_key: String,
        recovery_key: String,
    ) -> Result<Self, KelsError> {
        let mut event = previous_event.clone();
        event.kind = EventKind::Cnt;
        event.public_key = Some(public_key);
        event.rotation_hash = None;
        event.recovery_key = Some(recovery_key);
        event.recovery_hash = None;
        event.anchor = None;
        event.delegating_prefix = None;
        event.increment()?;
        Ok(event)
    }

    pub fn is_inception(&self) -> bool {
        self.kind == EventKind::Icp
    }

    pub fn is_delegated_inception(&self) -> bool {
        self.kind == EventKind::Dip
    }

    pub fn is_rotation(&self) -> bool {
        self.kind == EventKind::Rot
    }

    pub fn is_recovery(&self) -> bool {
        self.kind == EventKind::Rec
    }

    pub fn is_recovery_rotation(&self) -> bool {
        self.kind == EventKind::Ror
    }

    pub fn is_decommission(&self) -> bool {
        self.kind == EventKind::Dec
    }

    pub fn is_contest(&self) -> bool {
        self.kind == EventKind::Cnt
    }

    pub fn is_interaction(&self) -> bool {
        self.kind == EventKind::Ixn
    }

    pub fn is_establishment(&self) -> bool {
        self.kind.is_establishment()
    }

    pub fn reveals_recovery_key(&self) -> bool {
        self.kind.reveals_recovery_key()
    }

    pub fn requires_dual_signature(&self) -> bool {
        self.kind.requires_dual_signature()
    }

    pub fn decommissions(&self) -> bool {
        self.kind.decommissions()
    }
}

/// Signature record for storage.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "kels_key_event_signatures")]
#[serde(rename_all = "camelCase")]
pub struct EventSignature {
    /// Self-Addressing IDentifier
    #[said]
    pub said: String,
    /// The SAID of the event this signature is for
    pub event_said: String,
    /// The public key that created this signature (qb64 encoded)
    pub public_key: String,
    /// The signature (qb64 encoded)
    pub signature: String,
}

/// Signature with its signing public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEventSignature {
    /// The public key that created this signature (qb64 encoded)
    pub public_key: String,
    /// The signature (qb64 encoded)
    pub signature: String,
}

/// A key event paired with its signature(s).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedKeyEvent {
    /// The key event
    pub event: KeyEvent,
    /// Signatures over the event's SAID
    pub signatures: Vec<KeyEventSignature>,
}

impl SignedKeyEvent {
    /// Create a SignedKeyEvent with a single signature.
    pub fn new(event: KeyEvent, public_key: String, signature: String) -> Self {
        Self {
            event,
            signatures: vec![KeyEventSignature {
                public_key,
                signature,
            }],
        }
    }

    /// Create a SignedKeyEvent with dual signatures.
    pub fn new_recovery(
        event: KeyEvent,
        primary_public_key: String,
        primary_signature: String,
        secondary_public_key: String,
        secondary_signature: String,
    ) -> Self {
        Self {
            event,
            signatures: vec![
                KeyEventSignature {
                    public_key: primary_public_key,
                    signature: primary_signature,
                },
                KeyEventSignature {
                    public_key: secondary_public_key,
                    signature: secondary_signature,
                },
            ],
        }
    }

    /// Get signature by public key.
    pub fn signature(&self, public_key: &str) -> Option<&KeyEventSignature> {
        self.signatures.iter().find(|s| s.public_key == public_key)
    }

    /// Check if this has dual signatures.
    pub fn has_dual_signatures(&self) -> bool {
        self.signatures.len() >= 2
    }

    /// Create from a list of (public_key, signature) pairs.
    pub fn from_signatures(event: KeyEvent, sigs: Vec<(String, String)>) -> Self {
        Self {
            event,
            signatures: sigs
                .into_iter()
                .map(|(public_key, signature)| KeyEventSignature {
                    public_key,
                    signature,
                })
                .collect(),
        }
    }

    pub fn event_signatures(&self) -> Vec<EventSignature> {
        self.signatures
            .iter()
            .map(|s| {
                EventSignature::new(
                    self.event.said.clone(),
                    s.public_key.clone(),
                    s.signature.clone(),
                )
            })
            .collect()
    }
}

/// Response from batch event submission to KELS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use = "BatchSubmitResponse.accepted must be checked - events may be rejected"]
pub struct BatchSubmitResponse {
    /// SAID of first divergent event (None = no divergence)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diverged_at: Option<String>,
    /// True if all events were accepted
    pub accepted: bool,
}

/// Kind of audited item in KELS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum KelsAuditKind {
    /// A signed key event was audited
    SignedKeyEvent,
}

/// Type of audit event in KELS.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum KelsAuditEvent {
    /// Events were removed during recovery
    Recover,
    /// KEL was contested
    Contest,
}

/// KELS audit record for tracking deletions and contestations of key events.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "kels_audit_records")]
#[serde(rename_all = "camelCase")]
pub struct KelsAuditRecord {
    /// Self-Addressing IDentifier
    #[said]
    pub said: String,

    /// The registrant/KEL prefix this audit record relates to
    pub kel_prefix: String,

    /// Kind of item being audited
    pub kind: KelsAuditKind,

    /// Type of audit event
    pub event: KelsAuditEvent,

    /// Prefix of the deleted/contested item
    pub data_prefix: String,

    /// JSON-serialized data of the audited item(s)
    pub data_json: String,

    /// When this audit record was created
    #[created_at]
    pub recorded_at: StorageDatetime,
}

impl KelsAuditRecord {
    /// Create an audit record for events removed during recovery.
    pub fn for_recovery(
        kel_prefix: String,
        events: &[SignedKeyEvent],
    ) -> Result<Self, verifiable_storage::StorageError> {
        let data_json = serde_json::to_string(events)?;
        Self::create(
            kel_prefix.clone(),
            KelsAuditKind::SignedKeyEvent,
            KelsAuditEvent::Recover,
            kel_prefix,
            data_json,
        )
    }

    /// Create an audit record for a contested KEL.
    pub fn for_contest(
        kel_prefix: String,
        events: &[SignedKeyEvent],
    ) -> Result<Self, verifiable_storage::StorageError> {
        let data_json = serde_json::to_string(events)?;
        Self::create(
            kel_prefix.clone(),
            KelsAuditKind::SignedKeyEvent,
            KelsAuditEvent::Contest,
            kel_prefix,
            data_json,
        )
    }

    /// Deserialize the stored data as signed key events.
    pub fn as_signed_key_events(&self) -> Result<Vec<SignedKeyEvent>, serde_json::Error> {
        serde_json::from_str(&self.data_json)
    }
}

/// Single prefix request for batch KEL fetching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchKelPrefixRequest {
    /// The KEL prefix to fetch
    pub prefix: String,
    /// If provided, only return events with created_at > since (RFC3339 timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
}

/// Request to fetch multiple KELs in batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchKelsRequest {
    /// Prefixes to fetch, with optional since values
    pub prefixes: Vec<BatchKelPrefixRequest>,
}

/// KEL response from the KELS server.
///
/// Contains all events and optionally audit records if requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KelResponse {
    /// All key events (may include divergent events)
    pub events: Vec<SignedKeyEvent>,
    /// Audit records (only included when audit=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_records: Option<Vec<KelsAuditRecord>>,
}

/// Cached Key Event Log for KELS service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server-caching", derive(cacheable::Cacheable))]
#[cfg_attr(feature = "server-caching", cache(prefix = "kels:kel", ttl = 3600))]
#[serde(rename_all = "camelCase")]
pub struct CachedKel {
    #[cfg_attr(feature = "server-caching", cache_key(primary))]
    pub prefix: String,
    pub events: Vec<SignedKeyEvent>,
}

/// Cached contested KEL prefix for fast exists check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server-caching", derive(cacheable::Cacheable))]
#[cfg_attr(
    feature = "server-caching",
    cache(prefix = "kels:contested", ttl = 3600)
)]
#[serde(rename_all = "camelCase")]
pub struct ContestedPrefix {
    #[cfg_attr(feature = "server-caching", cache_key(primary))]
    pub prefix: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_kind_serialization() {
        assert_eq!(EventKind::Icp.as_str(), "icp");
        assert_eq!(EventKind::Dip.as_str(), "dip");
        assert_eq!(EventKind::Rot.as_str(), "rot");
        assert_eq!(EventKind::Ixn.as_str(), "ixn");
        assert_eq!(EventKind::Rec.as_str(), "rec");
        assert_eq!(EventKind::Ror.as_str(), "ror");
        assert_eq!(EventKind::Dec.as_str(), "dec");
        assert_eq!(EventKind::Cnt.as_str(), "cnt");
    }

    #[test]
    fn test_event_kind_parsing() {
        assert_eq!(EventKind::from_str("icp").unwrap(), EventKind::Icp);
        assert_eq!(EventKind::from_str("ICP").unwrap(), EventKind::Icp);
        assert_eq!(EventKind::from_str("cnt").unwrap(), EventKind::Cnt);
        assert!(EventKind::from_str("invalid").is_err());
    }

    #[test]
    fn test_event_kind_properties() {
        assert!(EventKind::Icp.is_inception());
        assert!(EventKind::Dip.is_inception());
        assert!(!EventKind::Rot.is_inception());

        assert!(EventKind::Icp.is_establishment());
        assert!(!EventKind::Ixn.is_establishment());

        assert!(EventKind::Rec.reveals_recovery_key());
        assert!(EventKind::Ror.reveals_recovery_key());
        assert!(EventKind::Dec.reveals_recovery_key());
        assert!(EventKind::Cnt.reveals_recovery_key());
        assert!(!EventKind::Rot.reveals_recovery_key());

        assert!(EventKind::Dec.decommissions());
        assert!(EventKind::Cnt.decommissions());
        assert!(!EventKind::Rec.decommissions());
    }

    #[test]
    fn test_event_kind_json() {
        let json = serde_json::to_string(&EventKind::Icp).unwrap();
        assert_eq!(json, "\"icp\"");

        let parsed: EventKind = serde_json::from_str("\"rec\"").unwrap();
        assert_eq!(parsed, EventKind::Rec);
    }
}
