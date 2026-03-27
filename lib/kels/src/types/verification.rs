//! Verification — proof-of-verification token for KEL state.
//!
//! `KelVerification` is the ONLY way to access verified KEL state. It cannot be
//! constructed directly — it must be obtained through `KelVerifier::into_verification()`.
//! Having a `KelVerification` proves the KEL was verified.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

use super::SignedKeyEvent;

/// A verified branch endpoint: the chain head and its last establishment event.
///
/// For a non-divergent KEL, there is one `BranchTip`. For divergent KELs, there
/// is one per branch. The `establishment_tip` provides the crypto state (public key,
/// rotation hash, recovery hash) for that branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchTip {
    /// The chain head — the latest event on this branch.
    pub tip: SignedKeyEvent,
    /// The last establishment event on this branch (provides signing key).
    pub establishment_tip: SignedKeyEvent,
}

/// Proof-of-verification token for KEL state.
///
/// Cannot be constructed directly — only via `KelVerifier::into_verification()`.
/// Having a `KelVerification` proves the KEL was fully verified. The SAID is a
/// content-addressable digest of the verified state — two `KelVerification`s with
/// the same SAID represent the same KEL state.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[crate_new]
pub struct KelVerification {
    #[said]
    said: String,
    prefix: String,
    delegating_prefix: Option<String>,
    branch_tips: Vec<BranchTip>,
    is_contested: bool,
    diverged_at_serial: Option<u64>,
    event_count: usize,
    rotation_count: usize,
    anchored_saids: BTreeSet<String>,
    queried_saids: BTreeSet<String>,
    /// Whether the KEL maintains proactive recovery rotation compliance:
    /// no more than `MAX_NON_REVEALING_EVENTS` non-revealing events between
    /// consecutive recovery-revealing events. Required to ensure all server
    /// operations (archival, contest, recovery) are bounded to a single page.
    proactive_ror_compliant: bool,
    /// Non-revealing events since the last recovery-revealing event.
    /// Preserved across resume so incremental verification continues tracking.
    events_since_last_revealing: usize,
}

impl KelVerification {
    /// The SAID (content-addressable digest) of this verification state.
    pub fn said(&self) -> &str {
        &self.said
    }

    /// The prefix this context is for.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The delegating prefix from the inception event, if it was a `dip`.
    pub fn delegating_prefix(&self) -> Option<&str> {
        self.delegating_prefix.as_deref()
    }

    /// All verified branch endpoints.
    pub fn branch_tips(&self) -> &[BranchTip] {
        &self.branch_tips
    }

    /// Current public key (qb64) from the last verified establishment event.
    /// Only meaningful for non-divergent KELs (single branch).
    pub fn current_public_key(&self) -> Option<&str> {
        if self.branch_tips.len() == 1 {
            self.branch_tips[0]
                .establishment_tip
                .event
                .public_key
                .as_deref()
        } else {
            None
        }
    }

    /// The last verified establishment event.
    /// Only meaningful for non-divergent KELs (single branch).
    pub fn last_establishment_event(&self) -> Option<&SignedKeyEvent> {
        if self.branch_tips.len() == 1 {
            Some(&self.branch_tips[0].establishment_tip)
        } else {
            None
        }
    }

    /// Whether the KEL is divergent (multiple branches).
    pub fn is_divergent(&self) -> bool {
        self.branch_tips.len() > 1
    }

    /// Whether the KEL has been contested (permanently frozen).
    pub fn is_contested(&self) -> bool {
        self.is_contested
    }

    /// The lowest serial where divergence occurs (if divergent).
    pub fn diverged_at_serial(&self) -> Option<u64> {
        self.diverged_at_serial
    }

    /// The total number of verified events in the KEL.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// The number of rotation (rot/ror) events in the verified KEL.
    pub fn rotation_count(&self) -> usize {
        self.rotation_count
    }

    /// Whether the KEL has been decommissioned.
    /// True if contested, or if the single branch tip is a decommission event.
    pub fn is_decommissioned(&self) -> bool {
        self.is_contested
            || (self.branch_tips.len() == 1 && self.branch_tips[0].tip.event.decommissions())
    }

    /// Compute the effective tail SAID from verified tips.
    ///
    /// - Single branch: tip event SAID
    /// - Contested: `hash("contested:{prefix}")` — deterministic across all nodes
    /// - Divergent: `hash("diverged:{prefix}")` — deterministic regardless of which
    ///   fork events each node has, avoiding wasted anti-entropy sync attempts
    pub fn effective_tail_said(&self) -> Option<String> {
        if self.branch_tips.is_empty() {
            return None;
        }
        if self.branch_tips.len() == 1 {
            return Some(self.branch_tips[0].tip.event.said.clone());
        }
        if self.is_contested {
            let input = format!("contested:{}", self.prefix);
            return Some(crate::hash_tip_saids(&[&input]));
        }
        let input = format!("diverged:{}", self.prefix);
        Some(crate::hash_tip_saids(&[&input]))
    }

    /// Check if a specific SAID was found anchored in the verified KEL.
    pub fn is_said_anchored(&self, said: &str) -> bool {
        self.anchored_saids.contains(said)
    }

    /// The full set of verified anchored SAIDs.
    pub fn anchored_saids(&self) -> &BTreeSet<String> {
        &self.anchored_saids
    }

    /// Whether all queried SAIDs were found anchored.
    pub fn anchors_all_saids(&self) -> bool {
        self.queried_saids.is_subset(&self.anchored_saids)
    }

    /// Whether the KEL maintains proactive recovery rotation compliance.
    pub fn is_proactive_ror_compliant(&self) -> bool {
        self.proactive_ror_compliant
    }

    /// Non-revealing events since the last recovery-revealing event.
    pub fn events_since_last_revealing(&self) -> usize {
        self.events_since_last_revealing
    }

    /// Whether the KEL is empty (no events).
    pub fn is_empty(&self) -> bool {
        self.branch_tips.is_empty()
    }
}
