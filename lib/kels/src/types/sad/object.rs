//! SAD object index types

use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

/// Index entry tracking a SAD object stored in MinIO.
///
/// Has its own content-addressed SAID. The `sad_said` field is the
/// SAID of the actual object in MinIO (foreign key to object storage).
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_objects")]
#[serde(rename_all = "camelCase")]
pub struct SadObjectEntry {
    #[said]
    pub said: String,
    pub sad_said: String,
}

/// Response for listing SAD object SAIDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadObjectListResponse {
    pub saids: Vec<String>,
    pub next_cursor: Option<String>,
}
