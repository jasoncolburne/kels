//! Shared policy-checking trait for chain authorization.
//!
//! `PolicyChecker` is the boundary between chain verifiers (KEL, SEL, IEL) and
//! the policy-resolution / KEL-anchoring machinery in `lib/policy`. The trait
//! takes SAIDs only — no event types — so the same trait serves any chain
//! primitive that needs anchoring + immunity checks.
//!
//! Two operations:
//! - `evaluate(said, policy)` — does `policy` evaluate satisfied for `said`?
//!   Returns an [`AnchorEvaluation`] with the satisfied flag plus the set of
//!   anchors whose local commitment could flip the outcome (`missing_anchors`).
//!   The verifier passes `event.said` and the policy SAID to check. For Icp
//!   events (self-authorization), the caller passes the event's declared
//!   policy; for v1+ events (advance against tracked state), the caller passes
//!   the branch's tracked policy.
//! - `is_immune(policy)` — does the policy declare `immune: true`? Used by
//!   verifiers and submit handlers to enforce the immunity rule on every
//!   policy introduction or evolution.
//!
//! Implementations live outside `lib/kels` to avoid circular deps (e.g.,
//! `lib/policy::AnchoredPolicyChecker` calls `evaluate_anchored_policy` to
//! check KEL anchoring and `Policy::is_immune` to check the immunity flag).

use crate::error::KelsError;

/// #156: structured outcome of [`PolicyChecker::evaluate`].
///
/// `missing_anchors` enumerates anchors whose local commitment *could* flip
/// the policy outcome — i.e., anchors on chains that are live (normal-tip or
/// divergent) or unknown locally. Anchors on contested or Dec'd chains are
/// *omitted* because they are permanent-fail (the awaited anchor can never
/// arrive on a contested/Dec'd chain).
///
/// Three result shapes the handler maps to wire-format outcomes:
///
/// | satisfied | missing_anchors | meaning | wire |
/// |---|---|---|---|
/// | `true`  | `[]`             | policy satisfied; commit | 200 |
/// | `false` | `[A1, A2, ...]`  | policy not yet satisfied; listed anchors are deferrable | 422 + `kel_anchor` deps |
/// | `false` | `[]`             | policy permanently unsatisfiable (any remaining anchors are on contested/Dec'd chains and permanent-fail) | 4xx-permanent |
///
/// This contract is load-bearing for the threshold-multi-chain re-park flow
/// (see #156 §Synthetic dispatch). If `missing_anchors` were to include
/// permanent-fail anchors, threshold-multi-chain parks would re-park
/// indefinitely on the contesting chain.
///
/// Each entry in `missing_anchors` is a KEL prefix — the endorser whose KEL
/// hasn't yet committed an Ixn anchoring the queried SAID. The handler pairs
/// this with the queried SAID (anchor_said) when constructing wire-format
/// `kel_anchor` deps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorEvaluation {
    pub satisfied: bool,
    pub missing_anchors: Vec<cesr::Digest256>,
}

#[async_trait::async_trait]
pub trait PolicyChecker: Send + Sync {
    /// Evaluate whether `policy` is satisfied for `said`, surfacing missing
    /// anchors per the [`AnchorEvaluation`] contract.
    ///
    /// Used by chain verifiers at every per-event policy gate. The caller
    /// supplies the SAID being authorized (the new event's SAID) and the
    /// policy SAID being evaluated against (the event's declared policy at
    /// Icp, or the branch's tracked policy at v1+). The implementation
    /// resolves the policy and runs the anchoring check.
    async fn evaluate(
        &self,
        said: &cesr::Digest256,
        policy: &cesr::Digest256,
    ) -> Result<AnchorEvaluation, KelsError>;

    /// Check whether `policy` declares `immune: true`.
    ///
    /// The immunity rule requires every policy introduced or evolved on a
    /// chain to be immune; verifiers and submit handlers reject the chain
    /// otherwise as a structural error.
    async fn is_immune(&self, policy: &cesr::Digest256) -> Result<bool, KelsError>;
}
