//! KELS Error Types

use std::fmt;

use thiserror::Error;

use crate::ErrorCode;

/// #156: deferrable dep payload — IEL event missing locally.
///
/// Used as the carrier for [`KelsError::MissingIelEvent`] and as a verifier
/// product (alongside [`MissingKelAnchor`]) the deferred-deps layer maps to
/// a 422 + `iel_event` dep. Boxed in the error variant to keep the
/// `KelsError` enum small (clippy::result_large_err).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingIelEvent {
    pub iel_prefix: cesr::Digest256,
    pub event_said: cesr::Digest256,
}

/// #156: permanent counterpart to [`MissingIelEvent`].
///
/// Carries the cross-IEL contamination, IEL chain-order regression, and
/// chain-integrity-breach cases the prior `BadIdentityBinding(String)`
/// merged together. Held by both [`KelsError::IdentityBindingViolation`]
/// and the corresponding `IelSatisfaction::PermanentFailure` (Gap 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityBindingViolation {
    pub reason: String,
}

impl IdentityBindingViolation {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for IdentityBindingViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

/// #156: deferrable dep payload — KEL anchor missing locally.
///
/// Used as the carrier for [`KelsError::MissingKelAnchor`]. The
/// deferred-deps layer maps to a 422 + `kel_anchor` dep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingKelAnchor {
    pub kel_prefix: cesr::Digest256,
    pub anchor_said: cesr::Digest256,
}

/// #156: permanent counterpart to [`MissingKelAnchor`].
///
/// Anchor present but invalid (bad sig, wrong key per policy) or anchor's
/// KEL in a structurally-failed state. The `reason` describes which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorPermanentFailure {
    pub kel_prefix: cesr::Digest256,
    pub anchor_said: cesr::Digest256,
    pub reason: String,
}

/// #156: deferrable dep payload — SAD object not present locally.
///
/// Carrier for [`KelsError::MissingSadObject`]. Used by the IEL/SE
/// verifier walks when a referenced SAD object (typically a Policy SAD
/// referenced by an Icp's `auth_policy` / `governance_policy`) hasn't
/// propagated to this node yet. The deferred-deps layer maps to a 422 +
/// `sad_object` dep; gossip parks under `pending:said:{S}` and drains on
/// `sad_updates(S)` arrival.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingSadObject {
    pub said: cesr::Digest256,
}

/// #156: deferrable failure accumulated during a verifier walk in
/// collect-mode (`SelVerifier::verify_page_collecting`,
/// `IelVerifier::verify_page_collecting`).
///
/// Each entry corresponds to one wire-format dep the deferred-deps layer
/// will surface in the 422 response. Permanent failures are NOT carried
/// here — they halt the walk with `Err(KelsError)` and are not deferrable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferredFailure {
    /// IEL event SAID not present in the bound IEL chain locally.
    /// Wire: `iel_event` dep.
    MissingIelEvent(MissingIelEvent),
    /// KEL anchor not yet committed by the named endorser.
    /// Wire: `kel_anchor` dep.
    MissingKelAnchor(MissingKelAnchor),
    /// SAD object referenced by an event hasn't propagated locally
    /// (typically a Policy SAD object referenced by an Icp/Evl event's
    /// `auth_policy` / `governance_policy`). Wire: `sad_object` dep.
    MissingSadObject(MissingSadObject),
}

impl DeferredFailure {
    pub fn missing_iel_event(iel_prefix: cesr::Digest256, event_said: cesr::Digest256) -> Self {
        Self::MissingIelEvent(MissingIelEvent {
            iel_prefix,
            event_said,
        })
    }

    pub fn missing_kel_anchor(kel_prefix: cesr::Digest256, anchor_said: cesr::Digest256) -> Self {
        Self::MissingKelAnchor(MissingKelAnchor {
            kel_prefix,
            anchor_said,
        })
    }

    pub fn missing_sad_object(said: cesr::Digest256) -> Self {
        Self::MissingSadObject(MissingSadObject { said })
    }
}

#[derive(Error, Clone, Debug)]
pub enum KelsError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("No current key available")]
    NoCurrentKey,

    #[error("No next key available")]
    NoNextKey,

    #[error("No recovery key available")]
    NoRecoveryKey,

    #[error("No staged key available")]
    NoStagedKey,

    #[error("No staged recovery key available")]
    NoStagedRecoveryKey,

    #[error("Currently staged keys")]
    CurrentlyStaged,

    #[error("Already staged recovery key")]
    AlreadyStagedRecovery,

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid key event: {0}")]
    InvalidKeyEvent(String),

    #[error("Invalid KEL: {0}")]
    InvalidKel(String),

    #[error("Invalid algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Not yet incepted")]
    NotIncepted,

    #[error("KEL is decommissioned")]
    KelDecommissioned,

    #[error("Submission failed: {0}")]
    SubmissionFailed(String),

    #[error("Offline mode: {0}")]
    OfflineMode(String),

    #[error("No recovery needed: {0}")]
    NoRecoveryNeeded(String),

    #[error("Key mismatch: {0}")]
    KeyMismatch(String),

    #[error("Divergence detected at: {diverged_at}, submission_accepted: {submission_accepted}")]
    DivergenceDetected {
        diverged_at: u64,
        submission_accepted: bool,
    },

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Server error ({1:?}): {0}")]
    ServerError(String, crate::types::ErrorCode),

    #[error("Missing keys for provider")]
    MissingKeys,

    #[error("HTTP request failed: {0}")]
    HttpError(String),

    #[error("Request timed out: {0}")]
    Timeout(String),

    #[error("JSON error: {0}")]
    JsonError(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Contested KEL: {0}")]
    ContestedKel(String),

    #[error("Contested IEL: {0}")]
    ContestedIel(String),

    #[error("IEL is decommissioned: {0}")]
    IelDecommissioned(String),

    #[error(
        "IEL is divergent: {0} — only `Cnt` resolves an IEL; bound an SE event to a non-divergent branch state instead"
    )]
    IelDivergent(String),

    #[error("Invalid IEL: {0}")]
    InvalidIel(String),

    #[error("Policy {policy} is not immune — write/governance/auth policies must be immune")]
    NotImmunePolicy { policy: String },

    #[error("Contest required: {reason}")]
    ContestRequired { reason: String },

    #[error("KEL diverged at: {0}")]
    Diverged(String),

    #[error("KEL is divergent")]
    Divergent,

    #[error("KEL frozen and requires recovery")]
    Frozen,

    #[error("Invalid serial: {0}")]
    InvalidSerial(String),

    #[error("Invalid SAID: {0}")]
    InvalidSaid(String),

    #[error("Invalid prefix: {0}")]
    InvalidPrefix(String),

    #[error("Invalid version: {0}")]
    InvalidVersion(String),

    /// #156: deferrable — verifier walked the bound KEL and could not find
    /// the anchor SAID; the anchor may commit later. Caller can defer on
    /// `(kel_prefix, anchor_said)` and replay when the KEL advances.
    #[error("Missing KEL anchor {} in KEL {}", .0.anchor_said, .0.kel_prefix)]
    MissingKelAnchor(Box<MissingKelAnchor>),

    /// #156: permanent — anchor present but invalid (bad signature, wrong
    /// key per policy) or anchor's KEL is in a structurally-failed state.
    /// Cleanup at the deferred-deps layer; surface 4xx-permanent.
    #[error("Anchor permanent failure for {} in KEL {}: {}", .0.anchor_said, .0.kel_prefix, .0.reason)]
    AnchorPermanentFailure(Box<AnchorPermanentFailure>),

    #[error("Hardware error: {0}")]
    HardwareError(String),

    #[error("HSM key not found: {0}")]
    HsmKeyNotFound(String),

    #[error("No ready nodes available in registry")]
    NoReadyNodes,

    #[error("All registries failed: {0}")]
    RegistryFailure(String),

    #[error("Invalid disclosure expression: {0}")]
    InvalidDisclosure(String),

    #[error("Evaluation required: would exceed non-evaluation event bound")]
    EvaluationRequired,

    #[error(
        "SAD Event Log diverged at version {at} — stage a repair to resolve before further updates"
    )]
    SelDivergent { at: u64 },

    #[error(
        "Nothing to repair — chain is linear and the cached tip matches the local store's owner-authored tip"
    )]
    NothingToRepair,

    #[error(
        "Chain has unverified events: {0} — cannot repair until policy is satisfied (verify the data source and re-run, or re-fetch a clean owner-local view)"
    )]
    ChainHasUnverifiedEvents(String),

    #[error("Pending events block repair/recovery: {0} — discard pending and retry")]
    PendingEventsBlockRepair(String),

    #[error(
        "SAD store payload missing for prefix {prefix} — index has SAID {said} but the keyed blob is absent (local-store corruption: manual filesystem manipulation, partial restore, or crash mid-write between SAID storage and index update)"
    )]
    // Stored as `String` (qb64 encoding) rather than `cesr::Digest256` to keep
    // `KelsError` small enough to pass `clippy::result_large_err`. Digest256 is
    // ~152 bytes; embedding two of them would balloon every `Result<_, KelsError>`
    // returned by the crate.
    SadStorePayloadMissing { prefix: String, said: String },

    /// #147: an SE batch contained an `Icp` but did not also contain an
    /// `Upd` at v1. The inception batch rule (`docs/design/sel/events.md`)
    /// requires `[Icp, Upd, ...]` minimum so every chain is born with both
    /// content and an IEL binding; lone-Icp batches are rejected.
    #[error("Incomplete inception: {0} — a batch containing Icp must also contain an Upd at v1")]
    IncompleteInception(String),

    /// #156 (split from prior `BadIdentityBinding`): deferrable — the
    /// named IEL event SAID isn't present in the bound IEL chain locally.
    /// The event may commit later via gossip propagation; caller can
    /// defer on `(iel_prefix, event_said)` and replay on chain advance.
    #[error("Missing IEL event {} in IEL {}", .0.event_said, .0.iel_prefix)]
    MissingIelEvent(Box<MissingIelEvent>),

    /// #156 (split from prior `BadIdentityBinding`): permanent — the
    /// SE event's `identity_event` binding is structurally invalid.
    /// Covers cross-IEL contamination (named SAID's IEL prefix doesn't
    /// match the SE chain's `identity`), IEL chain-order regression
    /// (named SAID regresses the SE branch's monotonic ratchet), and
    /// chain-integrity breaches (event referenced not in policy_history,
    /// walk-back failures). The `reason` describes which.
    ///
    /// HARD for ALL SE kinds (`Upd` / `Sea` / `Rpr` / `Cnt` / `Dec`) —
    /// a chain with no valid IEL binding cannot be recorded; chain
    /// integrity beats forensic preservation.
    #[error("Identity binding violation: {0}")]
    IdentityBindingViolation(IdentityBindingViolation),

    /// #156: deferrable — a SAD object referenced by a verifying event
    /// (typically a Policy SAD object referenced by an Icp/Evl event's
    /// `auth_policy` / `governance_policy` field) is not present in the
    /// local SAD object store. Object may commit later via gossip
    /// propagation; caller can defer on `said` and replay when the SAD
    /// object lands. Used by IEL/SE verifier collect-mode to accumulate
    /// `DeferredFailure::MissingSadObject`.
    #[error("Missing SAD object: {}", .0.said)]
    MissingSadObject(Box<MissingSadObject>),

    /// #147: `SadEventBuilder::decommission()` pre-flight refused
    /// because the SE chain is divergent. Generic — does not distinguish
    /// sealed vs. unsealed (the routing rules differ — sealed →
    /// `ContestRequired`, unsealed → `RepairRequired`); operators see the
    /// concrete next move from the server's response on a force-submit.
    #[error("Decommission blocked by divergence: {0}")]
    DecommissionBlockedByDivergence(String),

    /// Server-side chain re-verification of already-stored events failed.
    /// Indicates DB integrity loss or tampering — the receiver cannot
    /// confirm its own historical state, so it cannot accept new events.
    /// Surfaces as 500 (server-internal failure), not 409 (which is
    /// reserved for client-vs-state structural conflicts).
    #[error("Chain verification failed: {0}")]
    ChainVerificationFailed(String),
}

impl KelsError {
    /// Construct `ContestRequired` from a KEL-side reason. The three flavors
    /// (`_kel`, `_sel`, `_iel`) point at the same variant — the helper exists
    /// for call-site readability so a reader can tell which primitive's
    /// contest-trigger fired without reading the reason string.
    pub fn contest_required_kel(reason: impl Into<String>) -> Self {
        Self::ContestRequired {
            reason: reason.into(),
        }
    }

    /// Construct `ContestRequired` from an SEL-side reason.
    pub fn contest_required_sel(reason: impl Into<String>) -> Self {
        Self::ContestRequired {
            reason: reason.into(),
        }
    }

    /// Construct `ContestRequired` from an IEL-side reason.
    pub fn contest_required_iel(reason: impl Into<String>) -> Self {
        Self::ContestRequired {
            reason: reason.into(),
        }
    }

    /// #156: construct a deferrable [`KelsError::MissingIelEvent`].
    pub fn missing_iel_event(iel_prefix: cesr::Digest256, event_said: cesr::Digest256) -> Self {
        Self::MissingIelEvent(Box::new(MissingIelEvent {
            iel_prefix,
            event_said,
        }))
    }

    /// #156: construct a permanent [`KelsError::IdentityBindingViolation`].
    pub fn identity_binding_violation(reason: impl Into<String>) -> Self {
        Self::IdentityBindingViolation(IdentityBindingViolation::new(reason))
    }

    /// #156: construct a deferrable [`KelsError::MissingKelAnchor`].
    pub fn missing_kel_anchor(kel_prefix: cesr::Digest256, anchor_said: cesr::Digest256) -> Self {
        Self::MissingKelAnchor(Box::new(MissingKelAnchor {
            kel_prefix,
            anchor_said,
        }))
    }

    /// #156: construct a deferrable [`KelsError::MissingSadObject`].
    pub fn missing_sad_object(said: cesr::Digest256) -> Self {
        Self::MissingSadObject(Box::new(MissingSadObject { said }))
    }

    /// #156: construct a permanent [`KelsError::AnchorPermanentFailure`].
    pub fn anchor_permanent_failure(
        kel_prefix: cesr::Digest256,
        anchor_said: cesr::Digest256,
        reason: impl Into<String>,
    ) -> Self {
        Self::AnchorPermanentFailure(Box::new(AnchorPermanentFailure {
            kel_prefix,
            anchor_said,
            reason: reason.into(),
        }))
    }
}

impl From<cesr::CesrError> for KelsError {
    fn from(e: cesr::CesrError) -> Self {
        KelsError::CryptoError(e.to_string())
    }
}

impl From<reqwest::Error> for KelsError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            KelsError::Timeout(e.to_string())
        } else {
            KelsError::HttpError(e.to_string())
        }
    }
}

impl From<serde_json::Error> for KelsError {
    fn from(e: serde_json::Error) -> Self {
        KelsError::JsonError(e.to_string())
    }
}

impl From<std::io::Error> for KelsError {
    fn from(e: std::io::Error) -> Self {
        KelsError::IoError(e.to_string())
    }
}

impl From<verifiable_storage::StorageError> for KelsError {
    fn from(e: verifiable_storage::StorageError) -> Self {
        KelsError::StorageError(e.to_string())
    }
}

/// Read the response body text from an error response, preserving the HTTP
/// status code in the error if the body read itself fails.
pub(crate) async fn read_error_body(resp: reqwest::Response) -> Result<String, KelsError> {
    let status = resp.status();
    resp.text().await.map_err(|e| {
        KelsError::ServerError(
            format!("HTTP {status}: body unreadable: {e}"),
            ErrorCode::InternalError,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::Matter;

    #[test]
    fn test_error_display() {
        let err = KelsError::NotFound("test_key".to_string());
        assert!(err.to_string().contains("test_key"));

        let err = KelsError::NoCurrentKey;
        assert!(err.to_string().contains("current key"));

        let err = KelsError::DivergenceDetected {
            diverged_at: 5,
            submission_accepted: true,
        };
        assert!(err.to_string().contains("5"));
    }

    #[test]
    fn test_from_cesr_error() {
        // Create a CESR error by parsing invalid data
        let cesr_err = cesr::Signature::from_qb64("invalid").unwrap_err();
        let kels_err: KelsError = cesr_err.into();
        assert!(matches!(kels_err, KelsError::CryptoError(_)));
    }

    #[test]
    fn test_error_variants_display() {
        // Test all error variants have proper display messages
        let errors: Vec<KelsError> = vec![
            KelsError::NoNextKey,
            KelsError::NoRecoveryKey,
            KelsError::NoStagedKey,
            KelsError::NoStagedRecoveryKey,
            KelsError::CurrentlyStaged,
            KelsError::AlreadyStagedRecovery,
            KelsError::InvalidSignature("bad sig".to_string()),
            KelsError::InvalidKeyEvent("bad event".to_string()),
            KelsError::InvalidKel("bad kel".to_string()),
            KelsError::NotIncepted,
            KelsError::KelDecommissioned,
            KelsError::SubmissionFailed("failed".to_string()),
            KelsError::OfflineMode("offline".to_string()),
            KelsError::NoRecoveryNeeded("no recovery".to_string()),
            KelsError::KeyMismatch("mismatch".to_string()),
            KelsError::SignatureVerificationFailed,
            KelsError::VerificationFailed("verify failed".to_string()),
            KelsError::SigningFailed("sign failed".to_string()),
            KelsError::KeyGenerationFailed("keygen failed".to_string()),
            KelsError::MissingKeys,
            KelsError::Timeout("timed out".to_string()),
            KelsError::CryptoError("crypto error".to_string()),
            KelsError::CacheError("cache error".to_string()),
            KelsError::StorageError("storage error".to_string()),
            KelsError::ContestedKel("contested".to_string()),
            KelsError::ContestedIel("iel contested".to_string()),
            KelsError::IelDecommissioned("iel decommissioned".to_string()),
            KelsError::IelDivergent("iel diverged at v=7".to_string()),
            KelsError::InvalidIel("bad iel".to_string()),
            KelsError::NotImmunePolicy {
                policy: cesr::Digest256::blake3_256(b"policy").to_string(),
            },
            KelsError::contest_required_kel("recovery key revealed"),
            KelsError::contest_required_sel("sealed past submitter view"),
            KelsError::contest_required_iel("only Cnt resolves a divergent IEL"),
            KelsError::Diverged("diverged".to_string()),
            KelsError::Divergent,
            KelsError::Frozen,
            KelsError::InvalidSerial("bad serial".to_string()),
            KelsError::InvalidSaid("bad said".to_string()),
            KelsError::InvalidPrefix("bad prefix".to_string()),
            KelsError::InvalidVersion("bad version".to_string()),
            KelsError::missing_kel_anchor(
                cesr::Digest256::blake3_256(b"kel"),
                cesr::Digest256::blake3_256(b"anchor"),
            ),
            KelsError::anchor_permanent_failure(
                cesr::Digest256::blake3_256(b"kel"),
                cesr::Digest256::blake3_256(b"anchor"),
                "bad sig",
            ),
            KelsError::HardwareError("hw error".to_string()),
            KelsError::NoReadyNodes,
            KelsError::RegistryFailure("all failed".to_string()),
            KelsError::InvalidDisclosure("bad expression".to_string()),
            KelsError::EvaluationRequired,
            KelsError::SelDivergent { at: 7 },
            KelsError::NothingToRepair,
            KelsError::ChainHasUnverifiedEvents("local store policy_satisfied=false".to_string()),
            KelsError::PendingEventsBlockRepair("pending non-empty".to_string()),
            KelsError::SadStorePayloadMissing {
                prefix: cesr::Digest256::blake3_256(b"prefix").to_string(),
                said: cesr::Digest256::blake3_256(b"said").to_string(),
            },
            KelsError::IncompleteInception("missing v1 Upd".to_string()),
            KelsError::missing_iel_event(
                cesr::Digest256::blake3_256(b"iel"),
                cesr::Digest256::blake3_256(b"identity_event"),
            ),
            KelsError::identity_binding_violation("cross-IEL contamination"),
            KelsError::DecommissionBlockedByDivergence("chain divergent".to_string()),
            KelsError::ChainVerificationFailed("server-side existing chain re-verify".to_string()),
        ];

        for err in errors {
            // Just ensure Display doesn't panic and produces non-empty output
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_server_error_with_code() {
        use crate::types::ErrorCode;

        let err = KelsError::ServerError("not found".to_string(), ErrorCode::NotFound);
        let msg = err.to_string();
        assert!(msg.contains("not found"));
        assert!(msg.contains("NotFound"));
    }

    #[test]
    fn test_divergence_detected_fields() {
        let err = KelsError::DivergenceDetected {
            diverged_at: 10,
            submission_accepted: false,
        };
        let msg = err.to_string();
        assert!(msg.contains("10"));
        assert!(msg.contains("false"));
    }

    #[test]
    fn test_from_storage_error() {
        // Create a storage error by triggering a JSON parse error
        let json_err: Result<String, serde_json::Error> = serde_json::from_str("invalid");
        let storage_err =
            verifiable_storage::StorageError::SerializationError(json_err.unwrap_err());
        let kels_err: KelsError = storage_err.into();
        assert!(matches!(kels_err, KelsError::StorageError(_)));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let kels_err: KelsError = io_err.into();
        assert!(matches!(kels_err, KelsError::IoError(_)));
    }

    #[test]
    fn test_from_json_error() {
        let json_result: Result<String, serde_json::Error> = serde_json::from_str("invalid json");
        let json_err = json_result.unwrap_err();
        let kels_err: KelsError = json_err.into();
        assert!(matches!(kels_err, KelsError::JsonError(_)));
    }
}
