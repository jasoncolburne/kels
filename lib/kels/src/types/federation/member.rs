//! Federation member types

use serde::{Deserialize, Serialize};

/// Federation status information returned by the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationStatus {
    pub node_id: u64,
    pub self_prefix: cesr::Digest256,
    pub is_leader: bool,
    pub leader_id: Option<u64>,
    pub leader_prefix: Option<cesr::Digest256>,
    pub leader_url: Option<String>,
    pub term: u64,
    pub last_log_index: u64,
    pub last_applied: u64,
    pub members: Vec<cesr::Digest256>,
}

/// Compute the federation-IEL `governance_policy` threshold M(n) for member
/// count `n`. The convention is federation-specific (see
/// `docs/design/infrastructure/federation.md §Threshold formula`); other
/// identities choose their own governance thresholds and are not expected
/// to use this function.
///
/// - n in [0,5]: 3
/// - n in [6,9]: 4
/// - n >= 10:    ceil(n/3)
pub fn compute_federation_governance_threshold(n: usize) -> usize {
    match n {
        0..=5 => 3,
        6..=9 => 4,
        _ => n.div_ceil(3),
    }
}

/// Response from proposal submission, voting, and withdrawal endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalResponse {
    pub proposal_prefix: cesr::Digest256,
    pub status: String,
    pub votes_needed: usize,
    pub current_votes: usize,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_below_floor_uses_floor_of_three() {
        // n in [0, 5] returns 3 — protects small federations from trivial
        // collusion (per docs/design/infrastructure/federation.md
        // §Threshold formula).
        assert_eq!(compute_federation_governance_threshold(0), 3);
        assert_eq!(compute_federation_governance_threshold(1), 3);
        assert_eq!(compute_federation_governance_threshold(2), 3);
        assert_eq!(compute_federation_governance_threshold(3), 3);
        assert_eq!(compute_federation_governance_threshold(4), 3);
        assert_eq!(compute_federation_governance_threshold(5), 3);
    }

    #[test]
    fn test_mid_range_uses_four() {
        // n in [6, 9] returns 4 — bumps the bar before one-third scaling
        // takes over at n=10.
        assert_eq!(compute_federation_governance_threshold(6), 4);
        assert_eq!(compute_federation_governance_threshold(7), 4);
        assert_eq!(compute_federation_governance_threshold(8), 4);
        assert_eq!(compute_federation_governance_threshold(9), 4);
    }

    #[test]
    fn test_large_range_uses_one_third_quorum_ceiling() {
        // n >= 10 returns ceil(n / 3) — KERI-inspired F+1 immunity bound.
        assert_eq!(compute_federation_governance_threshold(10), 4); // ceil(10/3) = 4
        assert_eq!(compute_federation_governance_threshold(11), 4); // ceil(11/3) = 4
        assert_eq!(compute_federation_governance_threshold(12), 4); // ceil(12/3) = 4
        assert_eq!(compute_federation_governance_threshold(13), 5); // ceil(13/3) = 5
        assert_eq!(compute_federation_governance_threshold(15), 5); // ceil(15/3) = 5
        assert_eq!(compute_federation_governance_threshold(21), 7); // ceil(21/3) = 7
        assert_eq!(compute_federation_governance_threshold(25), 9); // ceil(25/3) = 9
        assert_eq!(compute_federation_governance_threshold(100), 34); // ceil(100/3) = 34
    }

    #[test]
    fn test_stair_transitions_are_sharp() {
        // The two stair-function transitions: 5→6 (3→4) and 9→10 (4→4 by
        // coincidence since ceil(10/3)=4, but the formula changes branch).
        assert_eq!(compute_federation_governance_threshold(5), 3);
        assert_eq!(compute_federation_governance_threshold(6), 4);
        assert_eq!(compute_federation_governance_threshold(9), 4);
        assert_eq!(compute_federation_governance_threshold(10), 4);
        // The 12→13 transition is the first real ceil(n/3) increase.
        assert_eq!(compute_federation_governance_threshold(12), 4);
        assert_eq!(compute_federation_governance_threshold(13), 5);
    }

    #[test]
    fn test_threshold_never_exceeds_member_count_for_realistic_federations() {
        // Federation operators size policies so that M(n) <= n is satisfiable.
        // For n >= 3 (the minimum realistic federation size per the §Floor
        // of 3 rationale), the formula always returns a value <= n.
        for n in 3..=50 {
            assert!(
                compute_federation_governance_threshold(n) <= n,
                "M({n}) = {} exceeded n",
                compute_federation_governance_threshold(n)
            );
        }
    }
}
