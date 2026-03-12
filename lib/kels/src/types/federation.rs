//! Federation status & approval threshold

use serde::{Deserialize, Serialize};

/// Federation status information returned by the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationStatus {
    pub node_id: u64,
    pub self_prefix: String,
    pub is_leader: bool,
    pub leader_id: Option<u64>,
    pub leader_prefix: Option<String>,
    pub leader_url: Option<String>,
    pub term: u64,
    pub last_log_index: u64,
    pub last_applied: u64,
    pub members: Vec<String>,
}

/// Compute the approval threshold for peer proposals given federation member count.
///
/// - n in [0,5]: 3
/// - n in [6,9]: 4
/// - n >= 10:    ceil(n/3)
pub fn compute_approval_threshold(n: usize) -> usize {
    match n {
        0..=5 => 3,
        6..=9 => 4,
        _ => n.div_ceil(3),
    }
}

/// Response from proposal submission, voting, and withdrawal endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalResponse {
    pub proposal_id: String,
    pub status: String,
    pub votes_needed: usize,
    pub current_votes: usize,
    pub message: String,
}
