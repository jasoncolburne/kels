//! KELS types for API requests and responses

use crate::error::KelsError;
use serde::{Deserialize, Serialize};
use std::cmp::{Eq, PartialEq};
use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use verifiable_storage::{Chained, SelfAddressed, StorageDatetime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Icp, // Inception
    Dip, // Delegated inception
    Rot, // Rotation
    Ixn, // Interaction (anchor)
    Rec, // Recovery (dual-signed)
    Ror, // Recovery rotation (dual-signed)
    Dec, // Decommission (dual-signed)
    Cnt, // Contest (dual-signed, freezes KEL)
}

impl EventKind {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KelMergeResult {
    Verified,          // Events accepted
    Recovered,         // Recovery succeeded
    Recoverable,       // Divergence - user can submit rec
    Contested,         // Both revealed recovery keys, KEL frozen
    Frozen,            // Already divergent, only rec/cnt allowed
    RecoveryProtected, // Recovery event protects this version
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    NotFound,
    Conflict,
    Contested,
    Frozen,
    Unauthorized,
    Gone,
    RecoveryProtected,
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
    pub code: ErrorCode,
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
        let mut icp = Self {
            said: String::new(),
            prefix: String::new(),
            previous: None,
            public_key: Some(public_key),
            rotation_hash: Some(rotation_hash),
            recovery_key: None,
            recovery_hash: Some(recovery_hash),
            kind: EventKind::Icp,
            anchor: None,
            delegating_prefix: None,
        };
        icp.derive_prefix()?;
        icp.derive_said()?;
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
            public_key: Some(public_key),
            rotation_hash: Some(rotation_hash),
            recovery_key: None,
            recovery_hash: Some(recovery_hash),
            kind: EventKind::Dip,
            anchor: None,
            delegating_prefix: Some(delegating_prefix),
        };
        dip.derive_prefix()?;
        dip.derive_said()?;
        Ok(dip)
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
#[must_use = "BatchSubmitResponse.accepted must be checked - events may be rejected"]
pub struct BatchSubmitResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diverged_at: Option<u64>,
    pub accepted: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchKelsRequest {
    pub prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KelResponse {
    pub events: Vec<SignedKeyEvent>, // May include divergent events at same version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_records: Option<Vec<KelsAuditRecord>>,
}

/// Response for paginated prefix listing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixListResponse {
    pub prefixes: Vec<PrefixState>,
    pub next_cursor: Option<String>,
}

/// A prefix with its latest SAID, used for bootstrap sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixState {
    pub prefix: String,
    pub said: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    #[default]
    Kels,
    Registry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Bootstrapping,
    Ready,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeRegistration {
    pub node_id: String,
    #[serde(default)]
    pub node_type: NodeType,
    pub kels_url: String,
    pub gossip_multiaddr: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterNodeRequest {
    pub node_id: String,
    #[serde(default)]
    pub node_type: NodeType,
    pub kels_url: String,
    pub gossip_multiaddr: String,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusUpdateRequest {
    pub node_id: String,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRequest {
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeregisterRequest {
    pub node_id: String,
}

/// Information about a registered KELS node (with client-computed fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub node_id: String,
    pub kels_url: String,
    pub gossip_multiaddr: String,
    pub status: NodeStatus,
    /// Measured latency in milliseconds (populated by discovery)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

impl From<NodeRegistration> for NodeInfo {
    fn from(reg: NodeRegistration) -> Self {
        Self {
            node_id: reg.node_id,
            kels_url: reg.kels_url,
            gossip_multiaddr: reg.gossip_multiaddr,
            status: reg.status,
            latency_ms: None,
        }
    }
}

/// Paginated response for node listings from the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodesResponse {
    pub nodes: Vec<NodeRegistration>,
    pub next_cursor: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedRequest<T> {
    pub payload: T,
    pub peer_id: String,
    pub public_key: String,
    pub signature: String,
}

// ==================== Peer Allowlist Types ====================

/// Scope of a peer in the registry federation.
///
/// - `Core`: Replicated to all registries via Raft consensus
/// - `Regional`: Local to this registry only, not shared across federation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PeerScope {
    /// Core peers are replicated across all registries in the federation via Raft consensus.
    /// Changes to core peers require consensus from the federation leader.
    Core,
    /// Regional peers are local to this registry only.
    /// They are not shared across the federation and can be managed independently.
    #[default]
    Regional,
}

impl PeerScope {
    /// Returns the string representation of the scope.
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerScope::Core => "core",
            PeerScope::Regional => "regional",
        }
    }
}

impl std::str::FromStr for PeerScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "core" => Ok(PeerScope::Core),
            "regional" => Ok(PeerScope::Regional),
            _ => Err(format!("Unknown peer scope: {}", s)),
        }
    }
}

impl std::fmt::Display for PeerScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "peer")]
#[serde(rename_all = "camelCase")]
pub struct Peer {
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
    pub peer_id: String,
    pub node_id: String,
    pub authorizing_kel: String,
    pub active: bool,
    /// Scope of this peer: core (replicated) or regional (local-only)
    pub scope: PeerScope,
    /// HTTP URL for the KELS service
    pub kels_url: String,
    /// libp2p multiaddr for gossip connections
    pub gossip_multiaddr: String,
}

impl Peer {
    /// Derive the HTTP URL for the gossip service from the multiaddr.
    /// Assumes HTTP is on port 80 on the same host as the gossip service.
    /// e.g., `/dns4/kels-gossip.ns.kels/tcp/4001` -> `http://kels-gossip.ns.kels:80`
    pub fn gossip_http_url(&self) -> Option<String> {
        // Parse multiaddr to extract host
        // Format: /dns4/<host>/tcp/<port> or /ip4/<ip>/tcp/<port>
        let parts: Vec<&str> = self.gossip_multiaddr.split('/').collect();
        if parts.len() >= 4 {
            let addr_type = parts[1];
            let host = parts[2];
            if addr_type == "dns4" || addr_type == "ip4" {
                return Some(format!("http://{}:80", host));
            }
        }
        None
    }

    pub fn deactivate(&self) -> Result<Self, verifiable_storage::StorageError> {
        let mut peer = self.clone();
        peer.active = false;
        peer.increment()?;
        Ok(peer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerHistory {
    pub prefix: String,
    pub records: Vec<Peer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeersResponse {
    pub peers: Vec<PeerHistory>,
}

// ==================== Raft Consensus State Types ====================

/// Raft vote state - tracks which node this node voted for in each term.
/// Chained for full audit trail of vote history.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "raft_vote")]
#[serde(rename_all = "camelCase")]
pub struct RaftVote {
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
    /// Raft node ID (unique constraint with version)
    pub node_id: u64,
    /// The Raft term number
    pub term: u64,
    /// Node ID that was voted for (None if no vote cast)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voted_for: Option<u64>,
    /// Whether this vote has been committed
    pub committed: bool,
}

/// Raft log entry - individual entries in the Raft log.
/// Chained for full audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "raft_log")]
#[serde(rename_all = "camelCase")]
pub struct RaftLogEntry {
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
    /// Raft node ID for this storage instance
    pub node_id: u64,
    /// Log index
    pub log_index: u64,
    /// Term when entry was received by leader
    pub term: u64,
    /// Node ID of the leader that proposed this entry
    pub leader_node_id: u64,
    /// Entry payload type: "blank", "normal", or "membership"
    pub payload_type: String,
    /// Serialized payload data (JSON)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_data: Option<String>,
}

/// Audit record for Raft log operations (truncate/purge).
/// Preserves full history of removed log entries.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "raft_log_audit")]
#[serde(rename_all = "camelCase")]
pub struct RaftLogAuditRecord {
    #[said]
    pub said: String,
    /// Node ID that performed the operation
    pub node_id: u64,
    /// Operation type: "truncate" or "purge"
    pub operation: String,
    /// JSON-serialized log entries that were removed
    pub entries_json: String,
    #[created_at]
    pub recorded_at: StorageDatetime,
}

impl RaftLogAuditRecord {
    /// Create an audit record for a truncate operation.
    pub fn for_truncate(
        node_id: u64,
        entries: &[RaftLogEntry],
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(
            node_id,
            "truncate".to_string(),
            serde_json::to_string(entries)?,
        )
    }

    /// Create an audit record for a purge operation.
    pub fn for_purge(
        node_id: u64,
        entries: &[RaftLogEntry],
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(
            node_id,
            "purge".to_string(),
            serde_json::to_string(entries)?,
        )
    }

    /// Deserialize the archived entries.
    pub fn entries(&self) -> Result<Vec<RaftLogEntry>, serde_json::Error> {
        serde_json::from_str(&self.entries_json)
    }
}

/// Raft state metadata - tracks purged and committed log positions.
/// Chained for full audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "raft_state")]
#[serde(rename_all = "camelCase")]
pub struct RaftState {
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
    /// Raft node ID (unique constraint with version)
    pub node_id: u64,
    /// Last purged log index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_purged_index: Option<u64>,
    /// Term of last purged entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_purged_term: Option<u64>,
    /// Node ID of leader for last purged entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_purged_node_id: Option<u64>,
    /// Committed log index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_index: Option<u64>,
    /// Term of committed entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_term: Option<u64>,
    /// Node ID of leader for committed entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_node_id: Option<u64>,
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

    #[test]
    fn test_peer_creation() {
        let peer = Peer::create(
            "12D3KooWExample".to_string(),
            "node-a".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Regional,
            "http://node-a:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        assert!(peer.active);
        assert_eq!(peer.version, 0);
        assert!(peer.previous.is_none());
        assert!(!peer.said.is_empty());
        // Prefix is derived from content hash, not manually set
        assert!(!peer.prefix.is_empty());
        assert_eq!(peer.scope, PeerScope::Regional);
        assert_eq!(peer.kels_url, "http://node-a:8080");
        assert_eq!(peer.gossip_multiaddr, "/ip4/127.0.0.1/tcp/4001");
    }

    #[test]
    fn test_peer_creation_with_core_scope() {
        let peer = Peer::create(
            "12D3KooWExample".to_string(),
            "node-b".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            "http://node-b:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4002".to_string(),
        )
        .unwrap();

        assert_eq!(peer.scope, PeerScope::Core);
    }

    #[test]
    fn test_peer_deactivation() {
        let peer = Peer::create(
            "12D3KooWExample".to_string(),
            "node-a".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Regional,
            "http://node-a:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        let deactivated = peer.deactivate().unwrap();

        assert!(!deactivated.active);
        assert_eq!(deactivated.version, 1);
        assert_eq!(deactivated.previous, Some(peer.said.clone()));
        assert_eq!(deactivated.prefix, peer.prefix);
    }

    // ==================== Test Helpers ====================

    fn make_blake3_digest(data: &str) -> String {
        use cesr::{Digest, Matter};
        Digest::blake3_256(data.as_bytes()).qb64()
    }

    fn make_secp256r1_key() -> String {
        use cesr::{KeyCode, Matter, PublicKey};
        // Valid compressed secp256r1 public key (33 bytes)
        let key_bytes = [
            0x02, // compressed prefix
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        PublicKey::from_raw(KeyCode::Secp256r1, key_bytes.to_vec())
            .unwrap()
            .qb64()
    }

    fn make_valid_icp() -> KeyEvent {
        KeyEvent {
            kind: EventKind::Icp,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: None,
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        }
    }

    // ==================== validate_structure tests ====================

    #[test]
    fn test_validate_structure_valid_icp() {
        let event = make_valid_icp();
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_icp_missing_public_key() {
        let mut event = make_valid_icp();
        event.public_key = None;
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires publicKey"));
    }

    #[test]
    fn test_validate_structure_icp_missing_rotation_hash() {
        let mut event = make_valid_icp();
        event.rotation_hash = None;
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires rotationHash"));
    }

    #[test]
    fn test_validate_structure_icp_missing_recovery_hash() {
        let mut event = make_valid_icp();
        event.recovery_hash = None;
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires recoveryHash"));
    }

    #[test]
    fn test_validate_structure_icp_forbids_previous() {
        let mut event = make_valid_icp();
        event.previous = Some(make_blake3_digest("prev"));
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have previous"));
    }

    #[test]
    fn test_validate_structure_icp_forbids_recovery_key() {
        let mut event = make_valid_icp();
        event.recovery_key = Some(make_secp256r1_key());
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have recoveryKey"));
    }

    #[test]
    fn test_validate_structure_icp_forbids_anchor() {
        let mut event = make_valid_icp();
        event.anchor = Some(make_blake3_digest("anchor"));
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have anchor"));
    }

    #[test]
    fn test_validate_structure_valid_dip() {
        let mut event = make_valid_icp();
        event.kind = EventKind::Dip;
        event.delegating_prefix = Some(make_blake3_digest("delegator"));
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_dip_requires_delegating_prefix() {
        let mut event = make_valid_icp();
        event.kind = EventKind::Dip;
        // Missing delegating_prefix
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires delegatingPrefix"));
    }

    #[test]
    fn test_validate_structure_valid_rot() {
        let event = KeyEvent {
            kind: EventKind::Rot,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: None,
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_rot_missing_previous() {
        let event = KeyEvent {
            kind: EventKind::Rot,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: None,
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: None,
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires previous"));
    }

    #[test]
    fn test_validate_structure_valid_ixn() {
        let event = KeyEvent {
            kind: EventKind::Ixn,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: None,
            rotation_hash: None,
            recovery_hash: None,
            recovery_key: None,
            anchor: Some(make_blake3_digest("anchor")),
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_ixn_forbids_public_key() {
        let event = KeyEvent {
            kind: EventKind::Ixn,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: None,
            recovery_hash: None,
            recovery_key: None,
            anchor: Some(make_blake3_digest("anchor")),
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have publicKey"));
    }

    #[test]
    fn test_validate_structure_valid_rec() {
        let event = KeyEvent {
            kind: EventKind::Rec,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_rec_missing_recovery_key() {
        let event = KeyEvent {
            kind: EventKind::Rec,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires recoveryKey"));
    }

    #[test]
    fn test_validate_structure_valid_dec() {
        let event = KeyEvent {
            kind: EventKind::Dec,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: None,
            recovery_hash: None,
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_dec_forbids_rotation_hash() {
        let event = KeyEvent {
            kind: EventKind::Dec,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: None,
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have rotationHash"));
    }

    #[test]
    fn test_validate_structure_self_referencing_previous() {
        let said = make_blake3_digest("said");
        let event = KeyEvent {
            kind: EventKind::Rot,
            said: said.clone(),
            prefix: make_blake3_digest("prefix"),
            previous: Some(said), // Same as said - circular!
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: None,
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("self-referencing"));
    }

    #[test]
    fn test_validate_structure_invalid_said_format() {
        let mut event = make_valid_icp();
        event.said = "not_a_valid_cesr_digest".to_string();
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("not a valid CESR digest"));
    }

    #[test]
    fn test_validate_structure_invalid_public_key_format() {
        let mut event = make_valid_icp();
        event.public_key = Some("not_a_valid_key".to_string());
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("not a valid CESR public key"));
    }

    // ==================== SignedKeyEvent tests ====================

    #[test]
    fn test_signed_key_event_equality_same_said() {
        let event = make_valid_icp();
        let sig1 = KeyEventSignature {
            public_key: "key1".to_string(),
            signature: "sig1".to_string(),
        };
        let sig2 = KeyEventSignature {
            public_key: "key2".to_string(),
            signature: "sig2".to_string(),
        };

        let signed1 = SignedKeyEvent {
            event: event.clone(),
            signatures: vec![sig1.clone(), sig2.clone()],
        };
        let signed2 = SignedKeyEvent {
            event: event.clone(),
            signatures: vec![sig2, sig1], // Different order
        };

        // Same SAID = equal (signature order doesn't matter)
        assert_eq!(signed1, signed2);
    }

    #[test]
    fn test_signed_key_event_equality_different_said() {
        let event1 = make_valid_icp();
        let mut event2 = make_valid_icp();
        event2.said = make_blake3_digest("different");

        let sig = KeyEventSignature {
            public_key: "key".to_string(),
            signature: "sig".to_string(),
        };

        let signed1 = SignedKeyEvent {
            event: event1,
            signatures: vec![sig.clone()],
        };
        let signed2 = SignedKeyEvent {
            event: event2,
            signatures: vec![sig],
        };

        assert_ne!(signed1, signed2);
    }

    #[test]
    fn test_signed_key_event_signature_lookup() {
        let event = make_valid_icp();
        let sig1 = KeyEventSignature {
            public_key: "key1".to_string(),
            signature: "sig1".to_string(),
        };
        let sig2 = KeyEventSignature {
            public_key: "key2".to_string(),
            signature: "sig2".to_string(),
        };

        let signed = SignedKeyEvent {
            event,
            signatures: vec![sig1.clone(), sig2.clone()],
        };

        assert_eq!(
            signed.signature("key1").map(|s| &s.signature),
            Some(&"sig1".to_string())
        );
        assert_eq!(
            signed.signature("key2").map(|s| &s.signature),
            Some(&"sig2".to_string())
        );
        assert!(signed.signature("key3").is_none());
    }

    // ==================== KeyEvent predicate tests ====================

    #[test]
    fn test_key_event_requires_dual_signature() {
        assert!(
            KeyEvent {
                kind: EventKind::Rec,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
        assert!(
            KeyEvent {
                kind: EventKind::Ror,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
        assert!(
            KeyEvent {
                kind: EventKind::Dec,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
        assert!(
            KeyEvent {
                kind: EventKind::Cnt,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
        assert!(!make_valid_icp().requires_dual_signature());
        assert!(
            !KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
    }

    #[test]
    fn test_key_event_is_inception() {
        assert!(make_valid_icp().is_inception());
        assert!(
            !KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .is_inception()
        );
    }

    #[test]
    fn test_key_event_is_delegated_inception() {
        assert!(
            KeyEvent {
                kind: EventKind::Dip,
                ..make_valid_icp()
            }
            .is_delegated_inception()
        );
        assert!(!make_valid_icp().is_delegated_inception());
    }

    #[test]
    fn test_key_event_is_establishment() {
        assert!(make_valid_icp().is_establishment());
        assert!(
            KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .is_establishment()
        );
        assert!(
            !KeyEvent {
                kind: EventKind::Ixn,
                ..make_valid_icp()
            }
            .is_establishment()
        );
    }

    // ==================== EventKind tests ====================

    #[test]
    fn test_event_kind_as_str() {
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
    fn test_event_kind_display() {
        assert_eq!(format!("{}", EventKind::Icp), "icp");
        assert_eq!(format!("{}", EventKind::Cnt), "cnt");
    }

    #[test]
    fn test_event_kind_from_str() {
        assert_eq!("icp".parse::<EventKind>().unwrap(), EventKind::Icp);
        assert_eq!("ICP".parse::<EventKind>().unwrap(), EventKind::Icp);
        assert_eq!("dip".parse::<EventKind>().unwrap(), EventKind::Dip);
        assert_eq!("rot".parse::<EventKind>().unwrap(), EventKind::Rot);
        assert_eq!("ixn".parse::<EventKind>().unwrap(), EventKind::Ixn);
        assert_eq!("rec".parse::<EventKind>().unwrap(), EventKind::Rec);
        assert_eq!("ror".parse::<EventKind>().unwrap(), EventKind::Ror);
        assert_eq!("dec".parse::<EventKind>().unwrap(), EventKind::Dec);
        assert_eq!("cnt".parse::<EventKind>().unwrap(), EventKind::Cnt);
    }

    #[test]
    fn test_event_kind_from_str_invalid() {
        let result = "invalid".parse::<EventKind>();
        assert!(result.is_err());
    }

    #[test]
    fn test_event_kind_is_inception() {
        assert!(EventKind::Icp.is_inception());
        assert!(EventKind::Dip.is_inception());
        assert!(!EventKind::Rot.is_inception());
        assert!(!EventKind::Ixn.is_inception());
    }

    #[test]
    fn test_event_kind_decommissions() {
        assert!(EventKind::Dec.decommissions());
        assert!(EventKind::Cnt.decommissions());
        assert!(!EventKind::Icp.decommissions());
        assert!(!EventKind::Rec.decommissions());
    }

    #[test]
    fn test_event_kind_reveals_rotation_key() {
        assert!(EventKind::Rot.reveals_rotation_key());
        assert!(EventKind::Rec.reveals_rotation_key());
        assert!(EventKind::Ror.reveals_rotation_key());
        assert!(!EventKind::Icp.reveals_rotation_key());
        assert!(!EventKind::Ixn.reveals_rotation_key());
    }

    #[test]
    fn test_event_kind_reveals_recovery_key() {
        assert!(EventKind::Rec.reveals_recovery_key());
        assert!(EventKind::Ror.reveals_recovery_key());
        assert!(EventKind::Dec.reveals_recovery_key());
        assert!(EventKind::Cnt.reveals_recovery_key());
        assert!(!EventKind::Icp.reveals_recovery_key());
        assert!(!EventKind::Rot.reveals_recovery_key());
    }

    // ==================== More KeyEvent predicate tests ====================

    #[test]
    fn test_key_event_is_rotation() {
        assert!(
            KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .is_rotation()
        );
        assert!(!make_valid_icp().is_rotation());
    }

    #[test]
    fn test_key_event_is_recover() {
        assert!(
            KeyEvent {
                kind: EventKind::Rec,
                ..make_valid_icp()
            }
            .is_recover()
        );
        assert!(!make_valid_icp().is_recover());
    }

    #[test]
    fn test_key_event_is_recovery_rotation() {
        assert!(
            KeyEvent {
                kind: EventKind::Ror,
                ..make_valid_icp()
            }
            .is_recovery_rotation()
        );
        assert!(!make_valid_icp().is_recovery_rotation());
    }

    #[test]
    fn test_key_event_is_decommission() {
        assert!(
            KeyEvent {
                kind: EventKind::Dec,
                ..make_valid_icp()
            }
            .is_decommission()
        );
        assert!(!make_valid_icp().is_decommission());
    }

    #[test]
    fn test_key_event_is_contest() {
        assert!(
            KeyEvent {
                kind: EventKind::Cnt,
                ..make_valid_icp()
            }
            .is_contest()
        );
        assert!(!make_valid_icp().is_contest());
    }

    #[test]
    fn test_key_event_is_interaction() {
        assert!(
            KeyEvent {
                kind: EventKind::Ixn,
                ..make_valid_icp()
            }
            .is_interaction()
        );
        assert!(!make_valid_icp().is_interaction());
    }

    #[test]
    fn test_key_event_reveals_rotation_key() {
        assert!(
            KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .reveals_rotation_key()
        );
        assert!(!make_valid_icp().reveals_rotation_key());
    }

    #[test]
    fn test_key_event_reveals_recovery_key() {
        assert!(
            KeyEvent {
                kind: EventKind::Rec,
                ..make_valid_icp()
            }
            .reveals_recovery_key()
        );
        assert!(!make_valid_icp().reveals_recovery_key());
    }

    #[test]
    fn test_key_event_has_recovery_hash() {
        assert!(make_valid_icp().has_recovery_hash());
        let mut event = make_valid_icp();
        event.recovery_hash = None;
        assert!(!event.has_recovery_hash());
    }

    #[test]
    fn test_key_event_decommissions() {
        assert!(
            KeyEvent {
                kind: EventKind::Dec,
                ..make_valid_icp()
            }
            .decommissions()
        );
        assert!(
            KeyEvent {
                kind: EventKind::Cnt,
                ..make_valid_icp()
            }
            .decommissions()
        );
        assert!(!make_valid_icp().decommissions());
    }

    // ==================== SignedKeyEvent additional tests ====================

    #[test]
    fn test_signed_key_event_new() {
        let event = make_valid_icp();
        let signed = SignedKeyEvent::new(event.clone(), "pubkey".to_string(), "sig".to_string());
        assert_eq!(signed.event.said, event.said);
        assert_eq!(signed.signatures.len(), 1);
        assert_eq!(signed.signatures[0].public_key, "pubkey");
        assert_eq!(signed.signatures[0].signature, "sig");
    }

    #[test]
    fn test_signed_key_event_new_recovery() {
        let event = make_valid_icp();
        let signed = SignedKeyEvent::new_recovery(
            event.clone(),
            "primary_key".to_string(),
            "primary_sig".to_string(),
            "recovery_key".to_string(),
            "recovery_sig".to_string(),
        );
        assert_eq!(signed.signatures.len(), 2);
        assert_eq!(signed.signatures[0].public_key, "primary_key");
        assert_eq!(signed.signatures[1].public_key, "recovery_key");
    }

    #[test]
    fn test_signed_key_event_from_signatures() {
        let event = make_valid_icp();
        let sigs = vec![
            ("key1".to_string(), "sig1".to_string()),
            ("key2".to_string(), "sig2".to_string()),
        ];
        let signed = SignedKeyEvent::from_signatures(event, sigs);
        assert_eq!(signed.signatures.len(), 2);
        assert_eq!(signed.signatures[0].public_key, "key1");
        assert_eq!(signed.signatures[1].signature, "sig2");
    }

    #[test]
    fn test_signed_key_event_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let event = make_valid_icp();
        let signed = SignedKeyEvent::new(event, "key".to_string(), "sig".to_string());

        let mut hasher = DefaultHasher::new();
        signed.hash(&mut hasher);
        let hash1 = hasher.finish();

        // Same event should produce same hash
        let signed2 = signed.clone();
        let mut hasher2 = DefaultHasher::new();
        signed2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_signed_key_event_equality_different_signature_count() {
        let event = make_valid_icp();
        let sig = KeyEventSignature {
            public_key: "key".to_string(),
            signature: "sig".to_string(),
        };

        let signed1 = SignedKeyEvent {
            event: event.clone(),
            signatures: vec![sig.clone()],
        };
        let signed2 = SignedKeyEvent {
            event,
            signatures: vec![sig.clone(), sig],
        };

        assert_ne!(signed1, signed2);
    }

    #[test]
    fn test_signed_key_event_equality_different_signatures() {
        let event = make_valid_icp();

        let signed1 = SignedKeyEvent {
            event: event.clone(),
            signatures: vec![KeyEventSignature {
                public_key: "key".to_string(),
                signature: "sig1".to_string(),
            }],
        };
        let signed2 = SignedKeyEvent {
            event,
            signatures: vec![KeyEventSignature {
                public_key: "key".to_string(),
                signature: "sig2".to_string(),
            }],
        };

        assert_ne!(signed1, signed2);
    }

    // ==================== Validate structure additional tests ====================

    #[test]
    fn test_validate_structure_dip_complete() {
        let event = KeyEvent {
            kind: EventKind::Dip,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: None,
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: None,
            anchor: None,
            delegating_prefix: Some(make_blake3_digest("delegator")),
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_dip_missing_delegating_prefix() {
        let event = KeyEvent {
            kind: EventKind::Dip,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: None,
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires delegatingPrefix"));
    }

    #[test]
    fn test_validate_structure_valid_ror() {
        let event = KeyEvent {
            kind: EventKind::Ror,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_valid_cnt() {
        let event = KeyEvent {
            kind: EventKind::Cnt,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: None,
            recovery_hash: None,
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    // ==================== NodeInfo tests ====================

    #[test]
    fn test_node_info_from_registration() {
        let reg = NodeRegistration {
            node_id: "node1".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://localhost:8080".to_string(),
            gossip_multiaddr: "/ip4/127.0.0.1/tcp/9000".to_string(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: NodeStatus::Ready,
        };

        let info: NodeInfo = reg.into();
        assert_eq!(info.node_id, "node1");
        assert_eq!(info.kels_url, "http://localhost:8080");
        assert_eq!(info.status, NodeStatus::Ready);
        assert!(info.latency_ms.is_none());
    }

    // ==================== BatchSubmitResponse tests ====================

    #[test]
    fn test_batch_submit_response_accepted() {
        let response = BatchSubmitResponse {
            accepted: true,
            diverged_at: None,
        };
        assert!(response.accepted);
        assert!(response.diverged_at.is_none());
    }

    #[test]
    fn test_batch_submit_response_diverged() {
        let response = BatchSubmitResponse {
            accepted: false,
            diverged_at: Some(5),
        };
        assert!(!response.accepted);
        assert_eq!(response.diverged_at, Some(5));
    }

    // ==================== Raft types tests ====================

    #[test]
    fn test_raft_vote_create() {
        let vote = RaftVote::create(1, 5, Some(2), false).unwrap();
        assert!(!vote.said.is_empty());
        assert!(!vote.prefix.is_empty());
        assert!(vote.previous.is_none());
        assert_eq!(vote.version, 0);
        assert_eq!(vote.node_id, 1);
        assert_eq!(vote.term, 5);
        assert_eq!(vote.voted_for, Some(2));
        assert!(!vote.committed);
    }

    #[test]
    fn test_raft_vote_create_no_vote() {
        let vote = RaftVote::create(1, 3, None, true).unwrap();
        assert_eq!(vote.voted_for, None);
        assert!(vote.committed);
    }

    #[test]
    fn test_raft_vote_increment() {
        let mut vote = RaftVote::create(1, 5, Some(2), false).unwrap();
        let original_said = vote.said.clone();
        let original_prefix = vote.prefix.clone();
        let original_version = vote.version;

        vote.term = 6;
        vote.voted_for = Some(3);
        vote.increment().unwrap();

        assert_ne!(vote.said, original_said);
        assert_eq!(vote.prefix, original_prefix);
        assert_eq!(vote.previous, Some(original_said));
        assert_eq!(vote.version, original_version + 1);
    }

    #[test]
    fn test_raft_vote_json_roundtrip() {
        let vote = RaftVote::create(42, 100, Some(5), true).unwrap();
        let json = serde_json::to_string(&vote).unwrap();
        let parsed: RaftVote = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, vote.said);
        assert_eq!(parsed.prefix, vote.prefix);
        assert_eq!(parsed.node_id, vote.node_id);
        assert_eq!(parsed.term, vote.term);
        assert_eq!(parsed.voted_for, vote.voted_for);
        assert_eq!(parsed.committed, vote.committed);
    }

    #[test]
    fn test_raft_log_entry_create() {
        let entry = RaftLogEntry::create(
            1,
            10,
            5,
            2,
            "normal".to_string(),
            Some("payload".to_string()),
        )
        .unwrap();

        assert!(!entry.said.is_empty());
        assert!(!entry.prefix.is_empty());
        assert!(entry.previous.is_none());
        assert_eq!(entry.version, 0);
        assert_eq!(entry.node_id, 1);
        assert_eq!(entry.log_index, 10);
        assert_eq!(entry.term, 5);
        assert_eq!(entry.leader_node_id, 2);
        assert_eq!(entry.payload_type, "normal");
        assert_eq!(entry.payload_data, Some("payload".to_string()));
    }

    #[test]
    fn test_raft_log_entry_create_blank() {
        let entry = RaftLogEntry::create(1, 0, 1, 0, "blank".to_string(), None).unwrap();

        assert_eq!(entry.payload_type, "blank");
        assert_eq!(entry.payload_data, None);
    }

    #[test]
    fn test_raft_log_entry_increment() {
        let mut entry =
            RaftLogEntry::create(1, 10, 5, 2, "normal".to_string(), Some("data".to_string()))
                .unwrap();
        let original_said = entry.said.clone();

        entry.log_index = 11;
        entry.term = 6;
        entry.increment().unwrap();

        assert_ne!(entry.said, original_said);
        assert_eq!(entry.previous, Some(original_said));
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn test_raft_log_entry_json_roundtrip() {
        let entry =
            RaftLogEntry::create(2, 5, 3, 1, "membership".to_string(), Some("{}".to_string()))
                .unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RaftLogEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, entry.said);
        assert_eq!(parsed.node_id, entry.node_id);
        assert_eq!(parsed.log_index, entry.log_index);
        assert_eq!(parsed.term, entry.term);
        assert_eq!(parsed.leader_node_id, entry.leader_node_id);
        assert_eq!(parsed.payload_type, entry.payload_type);
        assert_eq!(parsed.payload_data, entry.payload_data);
    }

    #[test]
    fn test_raft_state_create() {
        let state =
            RaftState::create(1, Some(5), Some(3), Some(2), Some(10), Some(4), Some(1)).unwrap();

        assert!(!state.said.is_empty());
        assert!(!state.prefix.is_empty());
        assert_eq!(state.node_id, 1);
        assert_eq!(state.last_purged_index, Some(5));
        assert_eq!(state.last_purged_term, Some(3));
        assert_eq!(state.last_purged_node_id, Some(2));
        assert_eq!(state.committed_index, Some(10));
        assert_eq!(state.committed_term, Some(4));
        assert_eq!(state.committed_node_id, Some(1));
    }

    #[test]
    fn test_raft_state_create_empty() {
        let state = RaftState::create(1, None, None, None, None, None, None).unwrap();

        assert_eq!(state.last_purged_index, None);
        assert_eq!(state.last_purged_term, None);
        assert_eq!(state.last_purged_node_id, None);
        assert_eq!(state.committed_index, None);
        assert_eq!(state.committed_term, None);
        assert_eq!(state.committed_node_id, None);
    }

    #[test]
    fn test_raft_state_increment() {
        let mut state = RaftState::create(1, None, None, None, None, None, None).unwrap();
        let original_said = state.said.clone();

        state.last_purged_index = Some(3);
        state.last_purged_term = Some(2);
        state.increment().unwrap();

        assert_ne!(state.said, original_said);
        assert_eq!(state.previous, Some(original_said));
        assert_eq!(state.version, 1);
    }

    #[test]
    fn test_raft_state_json_roundtrip() {
        let state = RaftState::create(
            5,
            Some(100),
            Some(50),
            Some(3),
            Some(150),
            Some(55),
            Some(4),
        )
        .unwrap();
        let json = serde_json::to_string(&state).unwrap();
        let parsed: RaftState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, state.said);
        assert_eq!(parsed.node_id, state.node_id);
        assert_eq!(parsed.last_purged_index, state.last_purged_index);
        assert_eq!(parsed.last_purged_term, state.last_purged_term);
        assert_eq!(parsed.last_purged_node_id, state.last_purged_node_id);
        assert_eq!(parsed.committed_index, state.committed_index);
        assert_eq!(parsed.committed_term, state.committed_term);
        assert_eq!(parsed.committed_node_id, state.committed_node_id);
    }

    #[test]
    fn test_raft_log_audit_record_for_truncate() {
        let entry1 =
            RaftLogEntry::create(1, 10, 5, 2, "normal".to_string(), Some("a".to_string())).unwrap();
        let entry2 =
            RaftLogEntry::create(1, 11, 5, 2, "normal".to_string(), Some("b".to_string())).unwrap();
        let entries = vec![entry1.clone(), entry2.clone()];

        let audit = RaftLogAuditRecord::for_truncate(1, &entries).unwrap();

        assert!(!audit.said.is_empty());
        assert_eq!(audit.node_id, 1);
        assert_eq!(audit.operation, "truncate");

        // Verify entries can be deserialized
        let recovered = audit.entries().unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].said, entry1.said);
        assert_eq!(recovered[1].said, entry2.said);
    }

    #[test]
    fn test_raft_log_audit_record_for_purge() {
        let entry = RaftLogEntry::create(1, 5, 3, 2, "blank".to_string(), None).unwrap();
        let entries = vec![entry.clone()];

        let audit = RaftLogAuditRecord::for_purge(1, &entries).unwrap();

        assert_eq!(audit.operation, "purge");
        let recovered = audit.entries().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].said, entry.said);
    }

    #[test]
    fn test_raft_log_audit_record_empty_entries() {
        let entries: Vec<RaftLogEntry> = vec![];
        let audit = RaftLogAuditRecord::for_truncate(1, &entries).unwrap();

        let recovered = audit.entries().unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_raft_log_audit_record_json_roundtrip() {
        let entry =
            RaftLogEntry::create(1, 10, 5, 2, "normal".to_string(), Some("data".to_string()))
                .unwrap();
        let audit = RaftLogAuditRecord::for_truncate(2, &[entry]).unwrap();

        let json = serde_json::to_string(&audit).unwrap();
        let parsed: RaftLogAuditRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, audit.said);
        assert_eq!(parsed.node_id, audit.node_id);
        assert_eq!(parsed.operation, audit.operation);
        assert_eq!(parsed.entries_json, audit.entries_json);
    }

    // ==================== PeerScope Tests ====================

    #[test]
    fn test_peer_scope_as_str() {
        assert_eq!(PeerScope::Core.as_str(), "core");
        assert_eq!(PeerScope::Regional.as_str(), "regional");
    }

    #[test]
    fn test_peer_scope_display() {
        assert_eq!(format!("{}", PeerScope::Core), "core");
        assert_eq!(format!("{}", PeerScope::Regional), "regional");
    }

    #[test]
    fn test_peer_scope_from_str() {
        use std::str::FromStr;

        assert_eq!(PeerScope::from_str("core").unwrap(), PeerScope::Core);
        assert_eq!(
            PeerScope::from_str("regional").unwrap(),
            PeerScope::Regional
        );
        assert_eq!(PeerScope::from_str("CORE").unwrap(), PeerScope::Core);
        assert_eq!(
            PeerScope::from_str("Regional").unwrap(),
            PeerScope::Regional
        );
        assert_eq!(
            PeerScope::from_str("REGIONAL").unwrap(),
            PeerScope::Regional
        );
    }

    #[test]
    fn test_peer_scope_from_str_invalid() {
        use std::str::FromStr;

        let result = PeerScope::from_str("invalid");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Unknown peer scope"));
    }

    #[test]
    fn test_peer_scope_default() {
        let scope = PeerScope::default();
        assert_eq!(scope, PeerScope::Regional);
    }

    #[test]
    fn test_peer_scope_serialization() {
        let core_json = serde_json::to_string(&PeerScope::Core).unwrap();
        assert_eq!(core_json, "\"core\"");

        let regional_json = serde_json::to_string(&PeerScope::Regional).unwrap();
        assert_eq!(regional_json, "\"regional\"");
    }

    #[test]
    fn test_peer_scope_deserialization() {
        let core: PeerScope = serde_json::from_str("\"core\"").unwrap();
        assert_eq!(core, PeerScope::Core);

        let regional: PeerScope = serde_json::from_str("\"regional\"").unwrap();
        assert_eq!(regional, PeerScope::Regional);
    }

    #[test]
    fn test_peer_scope_equality() {
        assert_eq!(PeerScope::Core, PeerScope::Core);
        assert_eq!(PeerScope::Regional, PeerScope::Regional);
        assert_ne!(PeerScope::Core, PeerScope::Regional);
    }

    #[test]
    fn test_peer_scope_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(PeerScope::Core);
        set.insert(PeerScope::Regional);
        set.insert(PeerScope::Core); // Duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&PeerScope::Core));
        assert!(set.contains(&PeerScope::Regional));
    }

    #[test]
    fn test_peer_scope_copy() {
        let scope = PeerScope::Core;
        let copied = scope; // Copy, not move
        assert_eq!(scope, copied);
        assert_eq!(scope, PeerScope::Core); // Original still usable
    }
}
