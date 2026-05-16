use std::collections::BTreeMap;

use serde::Serialize;

/// Status of a single endorser's anchoring for a credential.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EndorsementStatus {
    /// The endorser has anchored the credential SAID in their KEL.
    Endorsed,
    /// The endorser has not anchored the credential SAID.
    NotEndorsed,
    /// The endorser has anchored the poison hash (with or without the SAID).
    Poisoned,
    /// An error occurred verifying the endorser's KEL — chain not yet
    /// locally known, network/storage error, or other transient cause.
    /// Anchor MAY still arrive once the underlying condition resolves.
    /// Surfaced as deferrable in [`crate::AnchorEvaluation::missing_anchors`].
    KelError(String),
    /// The endorser's KEL is in a permanent-fail state (contested or
    /// decommissioned). The awaited anchor cannot land on a closed chain;
    /// callers must omit from [`crate::AnchorEvaluation::missing_anchors`]
    /// per the contract (see `lib/kels/src/types/policy_checker.rs`).
    KelPermanentFail(String),
}

/// Proof token for policy evaluation against KEL state.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyVerification {
    pub policy: cesr::Digest256,
    pub is_satisfied: bool,
    pub endorsements: BTreeMap<cesr::Digest256, EndorsementStatus>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub nested_verifications: BTreeMap<cesr::Digest256, PolicyVerification>,
}
