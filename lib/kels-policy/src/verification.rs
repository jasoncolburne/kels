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
    /// An error occurred verifying the endorser's KEL.
    KelError(String),
}

/// Proof token for policy evaluation against KEL state.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyVerification {
    pub policy: String,
    pub is_satisfied: bool,
    pub endorsements: BTreeMap<String, EndorsementStatus>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub nested_verifications: BTreeMap<String, PolicyVerification>,
}
