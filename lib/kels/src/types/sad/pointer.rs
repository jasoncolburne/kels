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

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageError};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<cesr::Digest256>,
    #[version]
    pub version: u64,
    /// The topic of this pointer chain (e.g., `"kels/exchange/v1/keys/mlkem"`).
    pub topic: String,
    /// SAID of the content object in the SAD store (None for v0 inception).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<cesr::Digest256>,
    /// SAID of the custody SAD (optional, controls readPolicy/nodes for the chain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custody: Option<cesr::Digest256>,
    /// SAID of the write policy (denormalized from custody for chain keying).
    /// Required — a pointer without a write_policy has no chain identity.
    pub write_policy: cesr::Digest256,
    /// SAID of the checkpoint policy — a higher-threshold policy that bounds
    /// divergence. An attacker who satisfies write_policy but can't satisfy
    /// checkpoint_policy has their fork bounded to ≤63 records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_policy: Option<cesr::Digest256>,
    /// Signals this record is a checkpoint — the PolicyChecker evaluates it
    /// against checkpoint_policy instead of (in addition to) write_policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_checkpoint: Option<bool>,
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
    let pointer = SadPointer::create(topic.to_string(), None, None, write_policy, None, None)?;
    Ok(pointer.prefix)
}

/// Proof-of-verification token for a SAD pointer chain.
///
/// Cannot be constructed outside this crate — only via `SadChainVerifier`.
/// Having a `SadPointerVerification` proves the chain was fully verified
/// (structural integrity and policy authorization checked).
#[derive(Debug, Clone)]
pub struct SadPointerVerification {
    tip: SadPointer,
    policy_satisfied: bool,
}

impl SadPointerVerification {
    /// Create a new verification token. Crate-internal only.
    pub(crate) fn new(tip: SadPointer, policy_satisfied: bool) -> Self {
        Self {
            tip,
            policy_satisfied,
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

    /// The write policy SAID.
    pub fn write_policy(&self) -> &cesr::Digest256 {
        &self.tip.write_policy
    }

    /// The pointer topic.
    pub fn topic(&self) -> &str {
        &self.tip.topic
    }

    /// Whether all write_policy checks were satisfied during verification.
    pub fn policy_satisfied(&self) -> bool {
        self.policy_satisfied
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
        let prefix1 = compute_sad_pointer_prefix(wp, "kels/exchange/v1/keys/mlkem").unwrap();
        let prefix2 = compute_sad_pointer_prefix(wp, "kels/exchange/v1/keys/mlkem").unwrap();
        assert_eq!(prefix1, prefix2);
    }

    #[test]
    fn test_compute_sad_pointer_prefix_different_inputs() {
        let prefix1 =
            compute_sad_pointer_prefix(test_digest(b"wp1"), "kels/exchange/v1/keys/mlkem").unwrap();
        let prefix2 =
            compute_sad_pointer_prefix(test_digest(b"wp2"), "kels/exchange/v1/keys/mlkem").unwrap();
        assert_ne!(prefix1, prefix2);

        let prefix3 =
            compute_sad_pointer_prefix(test_digest(b"wp1"), "kels/v1/other-kind").unwrap();
        assert_ne!(prefix1, prefix3);
    }

    #[test]
    fn test_sad_record_inception_no_content() {
        let pointer = SadPointer::create(
            "kels/exchange/v1/keys/mlkem".to_string(),
            None,
            None,
            test_digest(b"write-policy"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(pointer.version, 0);
        assert!(pointer.previous.is_none());
        assert!(pointer.content.is_none());
    }

    #[test]
    fn test_sad_record_chain_increment() {
        let mut pointer = SadPointer::create(
            "kels/exchange/v1/keys/mlkem".to_string(),
            None,
            None,
            test_digest(b"write-policy"),
            None,
            None,
        )
        .unwrap();

        let v0_said = pointer.said;
        let prefix = pointer.prefix;

        pointer.content = Some(test_digest(b"content_abc"));
        pointer.increment().unwrap();

        assert_eq!(pointer.version, 1);
        assert_eq!(pointer.previous, Some(v0_said));
        assert_eq!(pointer.prefix, prefix);
        assert_eq!(pointer.content, Some(test_digest(b"content_abc")));
    }

    #[test]
    fn test_sad_record_verify_said() {
        let pointer = SadPointer::create(
            "kels/exchange/v1/keys/mlkem".to_string(),
            None,
            None,
            test_digest(b"write-policy"),
            None,
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
            "kels/exchange/v1/keys/mlkem".to_string(),
            None,
            None,
            test_digest(b"write-policy"),
            None,
            None,
        )
        .unwrap();
        assert!(pointer.verify_prefix().is_ok());

        // Tamper with write_policy
        let mut tampered = pointer;
        tampered.write_policy = test_digest(b"tampered");
        tampered.derive_said().unwrap();
        assert!(tampered.verify_prefix().is_err());
    }
}
