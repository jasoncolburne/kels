use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Authenticated fetch request for a SAD object.
///
/// Used as `SignedRequest<SadFetchRequest>` for objects with `readPolicy`.
/// The `read_policy` field proves intent — the signer declares which readPolicy
/// they believe governs the record. Server rejects if it doesn't match.
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
    pub read_policy: Option<cesr::Digest256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
}

/// Request body for fetching or checking existence of a SAD object or pointer by SAID.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadFetchRequest {
    pub said: cesr::Digest256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
}

/// Request body for fetching a page of SAD pointer chain records.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadPointerPageRequest {
    pub prefix: cesr::Digest256,
    pub since: Option<cesr::Digest256>,
    pub limit: Option<usize>,
}

/// Request body for fetching the effective SAID of a SAD pointer chain.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadPointerEffectiveSaidRequest {
    pub prefix: cesr::Digest256,
}

/// Request body for listing repairs for a SAD pointer chain.
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
