//! SAD object index types

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Index entry tracking a SAD object stored in MinIO.
///
/// Has its own content-addressed SAID. The `sad_said` field is the
/// SAID of the actual object in MinIO (foreign key to object storage).
/// `custody` is the SAID of the custody SAD (if present).
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_objects")]
#[serde(rename_all = "camelCase")]
pub struct SadObjectEntry {
    #[said]
    pub said: cesr::Digest256,
    pub sad_said: cesr::Digest256,
    #[created_at]
    pub created_at: StorageDatetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custody: Option<cesr::Digest256>,
}

/// Response for listing SAD object SAIDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadObjectListResponse {
    pub saids: Vec<cesr::Digest256>,
    pub next_cursor: Option<cesr::Digest256>,
}
