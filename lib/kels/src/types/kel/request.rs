use serde::{Deserialize, Serialize};

/// Request body for fetching a page of KEL events.
#[derive(Debug, Deserialize, Serialize)]
pub struct KelPageRequest {
    pub prefix: String,
    pub since: Option<String>,
    pub limit: Option<usize>,
}

/// Request body for fetching the effective SAID of a KEL.
#[derive(Debug, Deserialize, Serialize)]
pub struct KelEffectiveSaidRequest {
    pub prefix: String,
}

/// Request body for checking if a KEL event exists by SAID.
#[derive(Debug, Deserialize, Serialize)]
pub struct KelEventExistsRequest {
    pub said: String,
}

/// Request body for listing recovery records for a KEL prefix.
#[derive(Debug, Deserialize, Serialize)]
pub struct KelRecoveriesRequest {
    pub prefix: String,
    pub limit: Option<usize>,
    pub offset: Option<u64>,
}

/// Request body for fetching archived adversary events for a specific recovery.
#[derive(Debug, Deserialize, Serialize)]
pub struct KelRecoveryEventsRequest {
    pub prefix: String,
    pub said: String,
    pub limit: Option<usize>,
    pub offset: Option<u64>,
}

/// Request body for fetching a federation proposal by prefix.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProposalRequest {
    pub prefix: String,
}
