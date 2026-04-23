use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Authenticated fetch request for a SAD object.
///
/// Used as `SignedRequest<SadFetchRequest>` for objects with `readPolicy`.
/// The `object_said` binds the request to a specific record — the server knows
/// the record's custody and evaluates the readPolicy directly.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct SignedSadFetchRequest {
    #[said]
    pub said: cesr::Digest256,
    #[created_at]
    pub created_at: StorageDatetime,
    pub nonce: cesr::Nonce256,
    pub object_said: cesr::Digest256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
}

/// Request body for fetching or checking existence of a SAD object or event by SAID.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadFetchRequest {
    pub said: cesr::Digest256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
}

/// Request body for fetching a page of SAD Event Log records.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadEventPageRequest {
    pub prefix: cesr::Digest256,
    pub since: Option<cesr::Digest256>,
    pub limit: Option<usize>,
}

/// Request body for fetching the effective SAID of a SAD Event Log.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadEventEffectiveSaidRequest {
    pub prefix: cesr::Digest256,
}

/// Response from SAD event submission.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use = "SubmitSadEventsResponse.applied must be checked — records may be rejected"]
pub struct SubmitSadEventsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diverged_at: Option<u64>,
    pub applied: bool,
}

/// Request body for listing repairs for a SAD Event Log.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadRepairsRequest {
    pub prefix: cesr::Digest256,
    pub limit: Option<usize>,
    pub offset: Option<u64>,
}

/// Request body for fetching archived records of a specific repair.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadRepairPageRequest {
    pub prefix: cesr::Digest256,
    pub said: cesr::Digest256,
    pub limit: Option<usize>,
    pub offset: Option<u64>,
}
