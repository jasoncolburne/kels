//! Shared policy-checking trait for chain authorization.
//!
//! `PolicyChecker` is the boundary between chain verifiers (KEL, SEL, IEL) and
//! the policy-resolution / KEL-anchoring machinery in `lib/policy`. The trait
//! takes SAIDs only — no event types — so the same trait serves any chain
//! primitive that needs anchoring + immunity checks.
//!
//! Two operations:
//! - `is_anchored(said, policy)` — does `policy` evaluate satisfied for `said`?
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

#[async_trait::async_trait]
pub trait PolicyChecker: Send + Sync {
    /// Check whether `policy` evaluates satisfied for `said`.
    ///
    /// Used by chain verifiers at every per-event policy gate. The caller
    /// supplies the SAID being authorized (the new event's SAID) and the
    /// policy SAID being evaluated against (the event's declared policy at
    /// Icp, or the branch's tracked policy at v1+). The implementation
    /// resolves the policy and runs the anchoring check.
    async fn is_anchored(
        &self,
        said: &cesr::Digest256,
        policy: &cesr::Digest256,
    ) -> Result<bool, KelsError>;

    /// Check whether `policy` declares `immune: true`.
    ///
    /// The immunity rule requires every policy introduced or evolved on a
    /// chain to be immune; verifiers and submit handlers reject the chain
    /// otherwise as a structural error.
    async fn is_immune(&self, policy: &cesr::Digest256) -> Result<bool, KelsError>;
}
