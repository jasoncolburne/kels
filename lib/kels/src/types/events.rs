//! Key event model & signatures

use std::{
    cmp::{Eq, PartialEq},
    collections::HashSet,
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use verifiable_storage::{Chained, SelfAddressed, StorageDatetime};

use crate::error::KelsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "kels/v1/icp")]
    Icp, // Inception
    #[serde(rename = "kels/v1/dip")]
    Dip, // Delegated inception
    #[serde(rename = "kels/v1/rot")]
    Rot, // Rotation
    #[serde(rename = "kels/v1/ixn")]
    Ixn, // Interaction (anchor)
    #[serde(rename = "kels/v1/rec")]
    Rec, // Recovery (dual-signed)
    #[serde(rename = "kels/v1/ror")]
    Ror, // Recovery rotation (dual-signed)
    #[serde(rename = "kels/v1/dec")]
    Dec, // Decommission (dual-signed)
    #[serde(rename = "kels/v1/cnt")]
    Cnt, // Contest (dual-signed, freezes KEL)
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Icp => "kels/v1/icp",
            Self::Dip => "kels/v1/dip",
            Self::Rot => "kels/v1/rot",
            Self::Ixn => "kels/v1/ixn",
            Self::Rec => "kels/v1/rec",
            Self::Ror => "kels/v1/ror",
            Self::Dec => "kels/v1/dec",
            Self::Cnt => "kels/v1/cnt",
        }
    }

    /// Parse a short event kind name (e.g. "ixn", "rot") as used by CLI tools.
    /// The version is implied — always creates the current version.
    pub fn from_short_name(s: &str) -> Result<Self, KelsError> {
        match s {
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

    /// Sort priority within the same serial (lower = earlier in sorted order).
    /// Ensures state-determining events (recovery, contest) sort after normal events,
    /// so the last event reflects the most significant event for announcements.
    pub fn sort_priority(&self) -> u8 {
        match self {
            Self::Icp => 0,
            Self::Dip => 1,
            Self::Ixn => 2,
            Self::Rot => 3,
            Self::Ror => 4,
            Self::Dec => 5,
            Self::Rec => 6,
            Self::Cnt => 7,
        }
    }

    const ALL: [Self; 8] = [
        Self::Icp,
        Self::Dip,
        Self::Ixn,
        Self::Rot,
        Self::Ror,
        Self::Dec,
        Self::Rec,
        Self::Cnt,
    ];

    /// Returns the sort priority mapping for use with `order_by_case` in DB queries.
    pub fn sort_priority_mapping() -> Vec<(&'static str, i64)> {
        Self::ALL
            .iter()
            .map(|k| (k.as_str(), k.sort_priority() as i64))
            .collect()
    }

    pub fn is_inception(&self) -> bool {
        matches!(self, Self::Icp | Self::Dip)
    }

    /// Establishment events have a public key
    pub fn is_establishment(&self) -> bool {
        !matches!(self, Self::Ixn)
    }

    pub fn reveals_rotation_key(&self) -> bool {
        matches!(self, Self::Rot) || self.reveals_recovery_key()
    }

    pub fn reveals_recovery_key(&self) -> bool {
        matches!(self, Self::Rec | Self::Ror | Self::Dec | Self::Cnt)
    }

    pub fn requires_dual_signature(&self) -> bool {
        self.reveals_recovery_key()
    }

    pub fn decommissions(&self) -> bool {
        matches!(self, Self::Dec | Self::Cnt)
    }

    /// Returns the DB string representations of all establishment event kinds.
    /// Used to query for the last establishment event without hardcoding kind strings in SQL.
    pub fn establishment_kinds() -> Vec<String> {
        Self::ALL
            .iter()
            .filter(|k| k.is_establishment())
            .map(|k| k.as_str().to_string())
            .collect()
    }

    /// Returns the DB string representations of kinds that reveal the recovery key.
    pub fn recovery_revealing_kinds() -> Vec<String> {
        Self::ALL
            .iter()
            .filter(|k| k.reveals_recovery_key())
            .map(|k| k.as_str().to_string())
            .collect()
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
        match s {
            "kels/v1/icp" => Ok(Self::Icp),
            "kels/v1/dip" => Ok(Self::Dip),
            "kels/v1/rot" => Ok(Self::Rot),
            "kels/v1/ixn" => Ok(Self::Ixn),
            "kels/v1/rec" => Ok(Self::Rec),
            "kels/v1/ror" => Ok(Self::Ror),
            "kels/v1/dec" => Ok(Self::Dec),
            "kels/v1/cnt" => Ok(Self::Cnt),
            _ => Err(KelsError::InvalidKeyEvent(format!(
                "Unknown event kind: {}",
                s
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KelMergeResult {
    Accepted,        // Events appended normally
    Recovered,       // Recovery succeeded
    Contested,       // Contest accepted, KEL locked
    Diverged,        // Divergent event accepted, KEL now frozen
    RecoverRequired, // Already divergent, submit rec to recover
    ContestRequired, // Adversary used recovery key, submit contest
}

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable]
#[serde(rename_all = "camelCase")]
pub struct KeyEvent {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub serial: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Digest of next signing key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_hash: Option<String>,
    /// Revealed only in rec/ror/dec/cnt events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<String>,
    /// Digest of next recovery key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_hash: Option<String>,
    pub kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    /// Only for dip events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegating_prefix: Option<String>,
}

impl KeyEvent {
    pub fn create_inception(
        public_key: String,
        rotation_hash: String,
        recovery_hash: String,
    ) -> Result<Self, KelsError> {
        match Self::create(
            Some(public_key),
            Some(rotation_hash),
            None,
            Some(recovery_hash),
            EventKind::Icp,
            None,
            None,
        ) {
            Ok(e) => Ok(e),
            Err(e) => Err(KelsError::StorageError(e.to_string())),
        }
    }

    pub fn create_delegated_inception(
        public_key: String,
        rotation_hash: String,
        recovery_hash: String,
        delegating_prefix: String,
    ) -> Result<Self, KelsError> {
        match Self::create(
            Some(public_key),
            Some(rotation_hash),
            None,
            Some(recovery_hash),
            EventKind::Dip,
            None,
            Some(delegating_prefix),
        ) {
            Ok(e) => Ok(e),
            Err(e) => Err(KelsError::StorageError(e.to_string())),
        }
    }

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
    pub fn is_recover(&self) -> bool {
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
    pub fn reveals_rotation_key(&self) -> bool {
        self.kind.reveals_rotation_key()
    }
    pub fn reveals_recovery_key(&self) -> bool {
        self.kind.reveals_recovery_key()
    }
    pub fn has_recovery_hash(&self) -> bool {
        self.recovery_hash.is_some()
    }
    pub fn requires_dual_signature(&self) -> bool {
        self.kind.requires_dual_signature()
    }
    pub fn decommissions(&self) -> bool {
        self.kind.decommissions()
    }

    /// Validates that the event has the correct fields for its kind.
    /// Returns Ok(()) if valid, Err with description if invalid.
    pub fn validate_structure(&self) -> Result<(), String> {
        use cesr::{Digest, DigestCode, KeyCode, Matter, PublicKey};

        // Helper to check field presence
        let require = |name: &str, present: bool| -> Result<(), String> {
            if present {
                Ok(())
            } else {
                Err(format!("{} event requires {}", self.kind, name))
            }
        };
        let forbid = |name: &str, present: bool| -> Result<(), String> {
            if present {
                Err(format!("{} event must not have {}", self.kind, name))
            } else {
                Ok(())
            }
        };
        let validate_blake3_said = |name: &str, value: &str| -> Result<(), String> {
            let digest = Digest::from_qb64(value)
                .map_err(|_| format!("{} is not a valid CESR digest", name))?;
            if digest.algorithm() != DigestCode::Blake3 {
                return Err(format!("{} must be a Blake3-256 digest", name));
            }
            Ok(())
        };
        let validate_secp256r1_key = |name: &str, value: &str| -> Result<(), String> {
            let key = PublicKey::from_qb64(value)
                .map_err(|_| format!("{} is not a valid CESR public key", name))?;
            if key.algorithm() != KeyCode::Secp256r1 {
                return Err(format!("{} must be a secp256r1 public key", name));
            }
            Ok(())
        };

        // Common: all events require said, prefix
        require("said", !self.said.is_empty())?;
        validate_blake3_said("said", &self.said)?;
        require("prefix", !self.prefix.is_empty())?;
        validate_blake3_said("prefix", &self.prefix)?;

        // Validate optional SAID fields when present
        if let Some(ref prev) = self.previous {
            validate_blake3_said("previous", prev)?;
        }
        forbid(
            "self-referencing previous",
            self.previous.as_ref() == Some(&self.said),
        )?;
        if let Some(ref hash) = self.rotation_hash {
            validate_blake3_said("rotationHash", hash)?;
        }
        if let Some(ref hash) = self.recovery_hash {
            validate_blake3_said("recoveryHash", hash)?;
        }
        if let Some(ref anchor) = self.anchor {
            validate_blake3_said("anchor", anchor)?;
        }

        // Validate public key fields when present
        if let Some(ref key) = self.public_key {
            validate_secp256r1_key("publicKey", key)?;
        }
        if let Some(ref key) = self.recovery_key {
            validate_secp256r1_key("recoveryKey", key)?;
        }

        match self.kind {
            EventKind::Icp => {
                // Inception: version=0, no previous, has public_key, rotation_hash, recovery_hash
                forbid("previous", self.previous.is_some())?;
                require("publicKey", self.public_key.is_some())?;
                require("rotationHash", self.rotation_hash.is_some())?;
                require("recoveryHash", self.recovery_hash.is_some())?;
                forbid("recoveryKey", self.recovery_key.is_some())?;
                forbid("anchor", self.anchor.is_some())?;
                forbid("delegatingPrefix", self.delegating_prefix.is_some())?;
            }
            EventKind::Dip => {
                // Delegated inception: same as icp but requires delegatingPrefix
                forbid("previous", self.previous.is_some())?;
                require("publicKey", self.public_key.is_some())?;
                require("rotationHash", self.rotation_hash.is_some())?;
                require("recoveryHash", self.recovery_hash.is_some())?;
                forbid("recoveryKey", self.recovery_key.is_some())?;
                forbid("anchor", self.anchor.is_some())?;
                require("delegatingPrefix", self.delegating_prefix.is_some())?;
            }
            EventKind::Rot => {
                // Rotation: version>0, has previous, public_key, rotation_hash
                require("previous", self.previous.is_some())?;
                require("publicKey", self.public_key.is_some())?;
                require("rotationHash", self.rotation_hash.is_some())?;
                forbid("recoveryKey", self.recovery_key.is_some())?;
                forbid("recoveryHash", self.recovery_hash.is_some())?;
                forbid("anchor", self.anchor.is_some())?;
                forbid("delegatingPrefix", self.delegating_prefix.is_some())?;
            }
            EventKind::Ixn => {
                // Interaction: version>0, has previous and anchor, no keys
                require("previous", self.previous.is_some())?;
                require("anchor", self.anchor.is_some())?;
                forbid("publicKey", self.public_key.is_some())?;
                forbid("rotationHash", self.rotation_hash.is_some())?;
                forbid("recoveryKey", self.recovery_key.is_some())?;
                forbid("recoveryHash", self.recovery_hash.is_some())?;
                forbid("delegatingPrefix", self.delegating_prefix.is_some())?;
            }
            EventKind::Rec => {
                // Recovery: version>0, has previous, all key fields
                require("previous", self.previous.is_some())?;
                require("publicKey", self.public_key.is_some())?;
                require("rotationHash", self.rotation_hash.is_some())?;
                require("recoveryKey", self.recovery_key.is_some())?;
                require("recoveryHash", self.recovery_hash.is_some())?;
                forbid("anchor", self.anchor.is_some())?;
                forbid("delegatingPrefix", self.delegating_prefix.is_some())?;
            }
            EventKind::Ror => {
                // Recovery rotation: same as rec
                require("previous", self.previous.is_some())?;
                require("publicKey", self.public_key.is_some())?;
                require("rotationHash", self.rotation_hash.is_some())?;
                require("recoveryKey", self.recovery_key.is_some())?;
                require("recoveryHash", self.recovery_hash.is_some())?;
                forbid("anchor", self.anchor.is_some())?;
                forbid("delegatingPrefix", self.delegating_prefix.is_some())?;
            }
            EventKind::Dec => {
                // Decommission: version>0, has previous, public_key, recovery_key
                // No future keys (rotation_hash, recovery_hash) since KEL ends
                require("previous", self.previous.is_some())?;
                require("publicKey", self.public_key.is_some())?;
                require("recoveryKey", self.recovery_key.is_some())?;
                forbid("rotationHash", self.rotation_hash.is_some())?;
                forbid("recoveryHash", self.recovery_hash.is_some())?;
                forbid("anchor", self.anchor.is_some())?;
                forbid("delegatingPrefix", self.delegating_prefix.is_some())?;
            }
            EventKind::Cnt => {
                // Contest: same as dec
                require("previous", self.previous.is_some())?;
                require("publicKey", self.public_key.is_some())?;
                require("recoveryKey", self.recovery_key.is_some())?;
                forbid("rotationHash", self.rotation_hash.is_some())?;
                forbid("recoveryHash", self.recovery_hash.is_some())?;
                forbid("anchor", self.anchor.is_some())?;
                forbid("delegatingPrefix", self.delegating_prefix.is_some())?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "kels_key_event_signatures")]
#[serde(rename_all = "camelCase")]
pub struct EventSignature {
    #[said]
    pub said: String,
    pub event_said: String,
    pub public_key: String, // qb64
    pub signature: String,  // qb64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEventSignature {
    pub public_key: String, // qb64
    pub signature: String,  // qb64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedKeyEvent {
    pub event: KeyEvent,
    pub signatures: Vec<KeyEventSignature>,
}

impl Eq for SignedKeyEvent {}

impl PartialEq for SignedKeyEvent {
    fn eq(&self, other: &Self) -> bool {
        if self.event.said != other.event.said {
            return false;
        }

        if self.signatures.len() != other.signatures.len() {
            return false;
        }

        let actual_signatures: HashSet<_> = self
            .signatures
            .iter()
            .map(|s| s.signature.clone())
            .collect();
        for signature in &other.signatures {
            if !actual_signatures.contains(&signature.signature) {
                return false;
            }
        }

        true
    }
}

impl Hash for SignedKeyEvent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.event.said.hash(state);
        for signature in self.signatures.clone() {
            signature.signature.hash(state);
        }
    }
}

impl SignedKeyEvent {
    pub fn new(event: KeyEvent, public_key: String, signature: String) -> Self {
        Self {
            event,
            signatures: vec![KeyEventSignature {
                public_key,
                signature,
            }],
        }
    }

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

    pub fn signature(&self, public_key: &str) -> Option<&KeyEventSignature> {
        self.signatures.iter().find(|s| s.public_key == public_key)
    }

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use = "BatchSubmitResponse.applied must be checked - events may be rejected"]
pub struct SubmitEventsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diverged_at: Option<u64>,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveSaidResponse {
    pub said: String,
    pub divergent: bool,
}

/// Audit record for tracking archived events during recovery/contest
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "kels_audit_records")]
#[serde(rename_all = "camelCase")]
pub struct KelsAuditRecord {
    #[said]
    pub said: String,
    pub kel_prefix: String,
    pub kind: EventKind, // rec or cnt
    pub data_json: String,
    #[created_at]
    pub recorded_at: StorageDatetime,
}

impl KelsAuditRecord {
    pub fn for_recovery(
        kel_prefix: String,
        events: &[SignedKeyEvent],
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(kel_prefix, EventKind::Rec, serde_json::to_string(events)?)
    }

    pub fn for_contest(
        kel_prefix: String,
        events: &[SignedKeyEvent],
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(kel_prefix, EventKind::Cnt, serde_json::to_string(events)?)
    }

    pub fn as_signed_key_events(&self) -> Result<Vec<SignedKeyEvent>, serde_json::Error> {
        serde_json::from_str(&self.data_json)
    }
}

/// NOTE: `build_page_bytes` in `services/kels/src/handlers.rs` manually constructs
/// this struct's JSON from cached bytes to avoid a serde round-trip. If you add or
/// rename fields here, update `build_page_bytes` to match.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedKeyEventPage {
    pub events: Vec<SignedKeyEvent>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server-caching", derive(cacheable::Cacheable))]
#[cfg_attr(feature = "server-caching", cache(prefix = "kels:kel", ttl = 3600))]
#[serde(rename_all = "camelCase")]
pub struct CachedKel {
    #[cfg_attr(feature = "server-caching", cache_key(primary))]
    pub prefix: String,
    pub events: Vec<SignedKeyEvent>,
}
