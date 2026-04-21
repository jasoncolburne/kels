//! SAD (Self-Addressing Data) pointer types for the replicated SADStore.
//!
//! Two layers:
//! - **SAD objects** — content-addressed JSON blobs stored/retrieved by SAID (MinIO).
//! - **Chained records** — versioned chains with deterministic prefix discovery and
//!   policy-based ownership. Each pointer references content in the SAD store via `content`.
//!
//! Chain prefix is derived from v0's `(write_policy SAID, topic)`. Prefix derivation
//! is fully deterministic: given the inception write_policy SAID and topic, anyone
//! can compute the chain prefix offline. Write_policy can evolve across versions.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageError};

use crate::error::KelsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SadPointerKind {
    #[serde(rename = "kels/sad/v1/pointer/icp")]
    Icp, // Inception (v0)
    #[serde(rename = "kels/sad/v1/pointer/upd")]
    Upd, // Update
    #[serde(rename = "kels/sad/v1/pointer/est")]
    Est, // Establish (checkpoint_policy declaration, no evaluation)
    #[serde(rename = "kels/sad/v1/pointer/evl")]
    Evl, // Evaluate (evaluated against checkpoint_policy)
    #[serde(rename = "kels/sad/v1/pointer/rpr")]
    Rpr, // Repair (resolves divergence, evaluates checkpoint_policy)
}

impl SadPointerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Icp => "kels/sad/v1/pointer/icp",
            Self::Upd => "kels/sad/v1/pointer/upd",
            Self::Est => "kels/sad/v1/pointer/est",
            Self::Evl => "kels/sad/v1/pointer/evl",
            Self::Rpr => "kels/sad/v1/pointer/rpr",
        }
    }

    /// Short pointer kind name (e.g. "icp", "upd") as used by CLI tools and responses.
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Icp => "icp",
            Self::Upd => "upd",
            Self::Est => "est",
            Self::Evl => "evl",
            Self::Rpr => "rpr",
        }
    }

    /// Parse a short pointer kind name (e.g. "icp", "upd") as used by CLI tools.
    pub fn from_short_name(s: &str) -> Result<Self, KelsError> {
        match s {
            "icp" => Ok(Self::Icp),
            "upd" => Ok(Self::Upd),
            "est" => Ok(Self::Est),
            "evl" => Ok(Self::Evl),
            "rpr" => Ok(Self::Rpr),
            _ => Err(KelsError::VerificationFailed(format!(
                "Unknown pointer kind: {}",
                s
            ))),
        }
    }

    /// True for kinds that evaluate checkpoint_policy (Evl, Rpr).
    /// These reset records_since_checkpoint and update last_checkpoint_version.
    pub fn evaluates_checkpoint(&self) -> bool {
        matches!(self, Self::Evl | Self::Rpr)
    }

    /// True for repair records (Rpr only).
    pub fn is_repair(&self) -> bool {
        matches!(self, Self::Rpr)
    }

    /// True for inception records (Icp only).
    pub fn is_inception(&self) -> bool {
        matches!(self, Self::Icp)
    }
}

impl fmt::Display for SadPointerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SadPointerKind {
    type Err = KelsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kels/sad/v1/pointer/icp" => Ok(Self::Icp),
            "kels/sad/v1/pointer/upd" => Ok(Self::Upd),
            "kels/sad/v1/pointer/est" => Ok(Self::Est),
            "kels/sad/v1/pointer/evl" => Ok(Self::Evl),
            "kels/sad/v1/pointer/rpr" => Ok(Self::Rpr),
            _ => Err(KelsError::VerificationFailed(format!(
                "Unknown pointer kind: {}",
                s
            ))),
        }
    }
}

/// A chained, self-addressed pointer in the SADStore.
///
/// The v0 (inception) pointer has `content: None` — this makes the prefix
/// fully deterministic from `write_policy` + `topic` alone. Content is added in v1+.
///
/// No `created_at` field — intentionally omitted so inception records are fully
/// deterministic for prefix computation.
///
/// Authorization is via the anchoring model: `write_policy` is consumer-side,
/// endorsing parties anchor the record's SAID in their KELs.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_pointers")]
#[serde(rename_all = "camelCase")]
pub struct SadPointer {
    #[said]
    pub said: cesr::Digest256,
    #[prefix]
    pub prefix: cesr::Digest256,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub previous: Option<cesr::Digest256>,
    #[version]
    pub version: u64,
    /// The topic of this pointer chain (e.g., `"kels/sad/v1/keys/mlkem"`).
    pub topic: String,
    /// The kind of this pointer record.
    pub kind: SadPointerKind,
    /// SAID of the content object in the SAD store (None for v0 inception).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content: Option<cesr::Digest256>,
    /// SAID of the custody SAD (optional, controls readPolicy/nodes for the chain).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub custody: Option<cesr::Digest256>,
    /// SAID of the write policy (denormalized from custody for chain keying).
    /// Required on `Icp` (prefix derivation) and optional on `Evl` (policy evolution).
    /// Forbidden on `Est`, `Upd`, `Rpr`. Absence on `Evl` means "pure checkpoint,
    /// no policy change" — verifier inherits the tracked policy from branch state.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub write_policy: Option<cesr::Digest256>,
    /// SAID of the checkpoint policy — a higher-threshold policy that bounds
    /// divergence. An attacker who satisfies write_policy but can't satisfy
    /// checkpoint_policy has their fork bounded to ≤63 records.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub checkpoint_policy: Option<cesr::Digest256>,
}

/// Compute the SAD chain prefix for a given write policy SAID and topic.
///
/// Anyone can call this offline — no server needed. The prefix is derived from
/// the v0 inception pointer content (with said+prefix as placeholders), which
/// contains only deterministic fields.
pub fn compute_sad_pointer_prefix(
    write_policy: cesr::Digest256,
    topic: &str,
) -> Result<cesr::Digest256, StorageError> {
    let pointer = SadPointer::create(
        topic.to_string(),
        SadPointerKind::Icp,
        None,
        None,
        Some(write_policy),
        None,
    )?;
    // Future-proof: if Icp's structural rules grow new required fields,
    // prefix derivation must not silently diverge from validate_structure.
    pointer
        .validate_structure()
        .map_err(StorageError::StorageError)?;
    Ok(pointer.prefix)
}

impl SadPointer {
    /// Validates that the pointer has the correct fields for its kind.
    /// Returns Ok(()) if valid, Err with description if invalid.
    pub fn validate_structure(&self) -> Result<(), String> {
        let require = |name: &str, present: bool| -> Result<(), String> {
            if present {
                Ok(())
            } else {
                Err(format!("{} pointer requires {}", self.kind, name))
            }
        };
        let forbid = |name: &str, present: bool| -> Result<(), String> {
            if present {
                Err(format!("{} pointer must not have {}", self.kind, name))
            } else {
                Ok(())
            }
        };

        match self.kind {
            SadPointerKind::Icp => {
                if self.version != 0 {
                    return Err(format!(
                        "Icp pointer must have version 0, got {}",
                        self.version
                    ));
                }
                require("writePolicy", self.write_policy.is_some())?;
                forbid("previous", self.previous.is_some())?;
                forbid("content", self.content.is_some())?;
                // checkpoint_policy is optional (non-discoverable chains may declare at v0)
            }
            SadPointerKind::Est => {
                if self.version != 1 {
                    return Err(format!(
                        "Est pointer must have version 1, got {}",
                        self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                require("checkpointPolicy", self.checkpoint_policy.is_some())?;
                forbid("writePolicy", self.write_policy.is_some())?;
            }
            SadPointerKind::Upd => {
                if self.version < 1 {
                    return Err(format!(
                        "Upd pointer must have version >= 1, got {}",
                        self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                forbid("checkpointPolicy", self.checkpoint_policy.is_some())?;
                forbid("writePolicy", self.write_policy.is_some())?;
            }
            SadPointerKind::Evl => {
                if self.version < 1 {
                    return Err(format!(
                        "Evl pointer must have version >= 1, got {}",
                        self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                // write_policy optional — present = policy evolution, absent = pure checkpoint
                // checkpoint_policy optional — allows policy evolution
            }
            SadPointerKind::Rpr => {
                if self.version < 1 {
                    return Err(format!(
                        "Rpr pointer must have version >= 1, got {}",
                        self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                forbid("checkpointPolicy", self.checkpoint_policy.is_some())?;
                forbid("writePolicy", self.write_policy.is_some())?;
            }
        }

        Ok(())
    }
}

/// Proof-of-verification token for a SAD pointer chain.
///
/// Cannot be constructed outside this crate — only via `SadChainVerifier`.
/// Having a `SadPointerVerification` proves the chain was fully verified
/// (structural integrity and policy authorization checked).
#[derive(Debug, Clone)]
pub struct SadPointerVerification {
    tip: SadPointer,
    tracked_write_policy: cesr::Digest256,
    policy_satisfied: bool,
    last_checkpoint_version: Option<u64>,
    establishment_version: Option<u64>,
}

impl SadPointerVerification {
    /// Create a new verification token. Crate-internal only.
    pub(crate) fn new(
        tip: SadPointer,
        tracked_write_policy: cesr::Digest256,
        policy_satisfied: bool,
        last_checkpoint_version: Option<u64>,
        establishment_version: Option<u64>,
    ) -> Self {
        Self {
            tip,
            tracked_write_policy,
            policy_satisfied,
            last_checkpoint_version,
            establishment_version,
        }
    }

    /// The latest verified pointer in the chain.
    pub fn current_record(&self) -> &SadPointer {
        &self.tip
    }

    /// The SAID of the content object referenced by the current pointer.
    pub fn current_content(&self) -> Option<&cesr::Digest256> {
        self.tip.content.as_ref()
    }

    /// The chain prefix.
    pub fn prefix(&self) -> &cesr::Digest256 {
        &self.tip.prefix
    }

    /// The tracked (effective) write policy SAID for the verified chain.
    ///
    /// Seeded by v0 (Icp) and updated whenever an Evl record carries a new
    /// write_policy *and* the evolution was authorized by the previous policy.
    /// Never `None` — v0 always establishes it. Evolutions that fail the soft
    /// write_policy check do not advance this value (the soft failure is also
    /// recorded in `policy_satisfied()`).
    ///
    /// For divergent chains, this reflects only the tie-break winner's branch
    /// state (higher version wins; equal versions break on lexicographically
    /// greater SAID). Divergent branches may legitimately carry different
    /// tracked policies, so callers that depend on chain-wide invariants
    /// should detect divergence via `effective_said` before consulting this.
    pub fn write_policy(&self) -> &cesr::Digest256 {
        &self.tracked_write_policy
    }

    /// The pointer topic.
    pub fn topic(&self) -> &str {
        &self.tip.topic
    }

    /// Whether all write_policy checks were satisfied during verification.
    pub fn policy_satisfied(&self) -> bool {
        self.policy_satisfied
    }

    /// The version of the most recent evaluated checkpoint, if any.
    /// Versions at or before this are sealed by checkpoint_policy.
    pub fn last_checkpoint_version(&self) -> Option<u64> {
        self.last_checkpoint_version
    }

    /// The version at which checkpoint_policy was established (v0 if Icp declared it, v1 if Est).
    /// Repair cannot truncate at or before this version.
    pub fn establishment_version(&self) -> Option<u64> {
        self.establishment_version
    }
}

/// A page of stored SAD pointers returned by the chain API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadPointerPage {
    pub pointers: Vec<SadPointer>,
    pub has_more: bool,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use verifiable_storage::{Chained, SelfAddressed};

    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    #[test]
    fn test_compute_sad_pointer_prefix_deterministic() {
        let wp = test_digest(b"write-policy");
        let prefix1 = compute_sad_pointer_prefix(wp, "kels/sad/v1/keys/mlkem").unwrap();
        let prefix2 = compute_sad_pointer_prefix(wp, "kels/sad/v1/keys/mlkem").unwrap();
        assert_eq!(prefix1, prefix2);
    }

    #[test]
    fn test_compute_sad_pointer_prefix_different_inputs() {
        let prefix1 =
            compute_sad_pointer_prefix(test_digest(b"wp1"), "kels/sad/v1/keys/mlkem").unwrap();
        let prefix2 =
            compute_sad_pointer_prefix(test_digest(b"wp2"), "kels/sad/v1/keys/mlkem").unwrap();
        assert_ne!(prefix1, prefix2);

        let prefix3 =
            compute_sad_pointer_prefix(test_digest(b"wp1"), "kels/v1/other-kind").unwrap();
        assert_ne!(prefix1, prefix3);
    }

    #[test]
    fn test_sad_record_inception_no_content() {
        let pointer = SadPointer::create(
            "kels/sad/v1/keys/mlkem".to_string(),
            SadPointerKind::Icp,
            None,
            None,
            Some(test_digest(b"write-policy")),
            None,
        )
        .unwrap();
        assert_eq!(pointer.version, 0);
        assert!(pointer.previous.is_none());
        assert!(pointer.content.is_none());
        assert_eq!(pointer.kind, SadPointerKind::Icp);
    }

    #[test]
    fn test_sad_record_chain_increment() {
        let mut pointer = SadPointer::create(
            "kels/sad/v1/keys/mlkem".to_string(),
            SadPointerKind::Icp,
            None,
            None,
            Some(test_digest(b"write-policy")),
            None,
        )
        .unwrap();

        let v0_said = pointer.said;
        let prefix = pointer.prefix;

        pointer.content = Some(test_digest(b"content_abc"));
        pointer.kind = SadPointerKind::Upd;
        pointer.increment().unwrap();

        assert_eq!(pointer.version, 1);
        assert_eq!(pointer.previous, Some(v0_said));
        assert_eq!(pointer.prefix, prefix);
        assert_eq!(pointer.content, Some(test_digest(b"content_abc")));
    }

    #[test]
    fn test_sad_record_verify_said() {
        let pointer = SadPointer::create(
            "kels/sad/v1/keys/mlkem".to_string(),
            SadPointerKind::Icp,
            None,
            None,
            Some(test_digest(b"write-policy")),
            None,
        )
        .unwrap();
        assert!(pointer.verify_said().is_ok());

        // Tamper with content
        let mut tampered = pointer;
        tampered.topic = "kels/v1/tampered".to_string();
        assert!(tampered.verify_said().is_err());
    }

    #[test]
    fn test_sad_record_verify_prefix() {
        let pointer = SadPointer::create(
            "kels/sad/v1/keys/mlkem".to_string(),
            SadPointerKind::Icp,
            None,
            None,
            Some(test_digest(b"write-policy")),
            None,
        )
        .unwrap();
        assert!(pointer.verify_prefix().is_ok());

        // Tamper with write_policy
        let mut tampered = pointer;
        tampered.write_policy = Some(test_digest(b"tampered"));
        tampered.derive_said().unwrap();
        assert!(tampered.verify_prefix().is_err());
    }
}
