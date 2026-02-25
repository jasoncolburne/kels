//! MergeContext — proof-of-verification token for KEL state.
//!
//! `MergeContext` is the ONLY way to access verified KEL state. It cannot be
//! constructed directly — it must be obtained through `KelVerifier::into_verification()`.
//! Having a `MergeContext` proves the KEL was verified.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

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
/// Having a `MergeContext` proves the KEL was fully verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    prefix: String,
    branch_tips: Vec<BranchTip>,
    is_contested: bool,
    diverged_at_serial: Option<u64>,
    anchored_saids: HashSet<String>,
    queried_saids: HashSet<String>,
}

impl Verification {
    /// Internal constructor — only `KelVerifier` should call this.
    pub(crate) fn new(
        prefix: String,
        branch_tips: Vec<BranchTip>,
        is_contested: bool,
        diverged_at_serial: Option<u64>,
        anchored_saids: HashSet<String>,
        queried_saids: HashSet<String>,
    ) -> Self {
        Self {
            prefix,
            branch_tips,
            is_contested,
            diverged_at_serial,
            anchored_saids,
            queried_saids,
        }
    }

    /// The prefix this context is for.
    pub fn prefix(&self) -> &str {
        &self.prefix
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

    /// Whether the KEL has been decommissioned.
    /// True if contested, or if the single branch tip is a decommission event.
    pub fn is_decommissioned(&self) -> bool {
        self.is_contested
            || (self.branch_tips.len() == 1 && self.branch_tips[0].tip.event.decommissions())
    }

    /// Compute the effective tail SAID from verified tips.
    pub fn effective_tail_said(&self) -> Option<String> {
        if self.branch_tips.is_empty() {
            return None;
        }
        if self.branch_tips.len() == 1 {
            return Some(self.branch_tips[0].tip.event.said.clone());
        }
        let mut tip_saids: Vec<&str> = self
            .branch_tips
            .iter()
            .map(|bt| bt.tip.event.said.as_str())
            .collect();
        tip_saids.sort();
        Some(crate::hash_tip_saids(&tip_saids))
    }

    /// Check if a specific SAID was found anchored in the verified KEL.
    pub fn is_said_anchored(&self, said: &str) -> bool {
        self.anchored_saids.contains(said)
    }

    /// The full set of verified anchored SAIDs.
    pub fn anchored_saids(&self) -> &HashSet<String> {
        &self.anchored_saids
    }

    /// Whether all queried SAIDs were found anchored.
    pub fn anchors_all_saids(&self) -> bool {
        self.queried_saids.is_subset(&self.anchored_saids)
    }

    /// Whether the KEL is empty (no events).
    pub fn is_empty(&self) -> bool {
        self.branch_tips.is_empty()
    }
}
