use serde::{Deserialize, Serialize};

/// Request body for fetching or checking existence of a SAD object or pointer by SAID.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadRequest {
    pub said: String,
}

/// Request body for fetching a page of SAD pointer chain records.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadPointerPageRequest {
    pub prefix: String,
    pub since: Option<String>,
    pub limit: Option<usize>,
}

/// Request body for fetching the effective SAID of a SAD pointer chain.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadPointerEffectiveSaidRequest {
    pub prefix: String,
}

/// Request body for listing repairs for a SAD pointer chain.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadRepairsRequest {
    pub prefix: String,
    pub limit: Option<usize>,
    pub offset: Option<u64>,
}

/// Request body for fetching archived records of a specific repair.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadRepairPageRequest {
    pub prefix: String,
    pub said: String,
    pub limit: Option<usize>,
    pub offset: Option<u64>,
}
