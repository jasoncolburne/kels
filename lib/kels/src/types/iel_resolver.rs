//! Cross-chain IEL access for SE-side verification (per #147).
//!
//! `IelResolver` is a separate concern from [`PolicyChecker`](crate::PolicyChecker):
//! the policy checker evaluates `(said, policy)` anchoring without any
//! awareness of how the policy was discovered, while the resolver knows how
//! to navigate an IEL chain to extract the policy-at-event lookup that the
//! SE verifier needs to authorize a `Upd` / `Sea` / `Rpr` / `Cnt` / `Dec`.
//!
//! Splitting the two responsibilities keeps `PolicyChecker` reusable across
//! KEL / SEL / IEL primitives (it takes SAIDs only) and keeps IEL chain
//! navigation out of policy evaluation.
//!
//! Production impls back this trait with the IEL repository (server-side) or
//! HTTP client + cached `IelVerification` (builder-side). Both rely on the
//! `IelVerification::auth_policy_at` / `governance_policy_at` accessors,
//! which are SAID-keyed direct lookups with carry-forward already applied by
//! the IEL verifier — there is no chain-walk for the policy value itself.
//!
//! Cross-chain divergence guard: `resolve_*_at` surfaces
//! [`KelsError::IelDivergent`] when the bound IEL event sits at-or-after the
//! IEL's `first_divergent_version`. Pre-divergence shared events resolve
//! cleanly even on a divergent IEL.

use std::{cmp::Ordering, collections::HashMap};

use super::iel::{IdentityEvent, IdentityEventKind};
use crate::KelsError;

/// The position of an IEL event within its chain's canonical order.
///
/// Returned (in batches) by [`IelResolver::iel_chain_positions`] and consumed
/// by the SE verifier's monotonic-ratchet check. Two positions are compared
/// via [`IelChainPosition::try_cmp`], which returns
/// [`KelsError::IelDivergent`] when comparison would cross divergent IEL
/// branches.
///
/// `branch_marker = None` indicates the event lives in the pre-divergence
/// shared prefix (or the IEL is non-divergent — both cases compare cleanly
/// against any other position). `branch_marker = Some(id)` marks an event on
/// a specific post-divergence branch; two positions sharing the same
/// `branch_marker` compare via canonical chain order, while differing
/// `branch_marker`s surface `IelDivergent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IelChainPosition {
    /// Event version on its (possibly divergent) branch.
    pub version: u64,
    /// Event kind — used in the canonical IEL chain sort key.
    pub kind: IdentityEventKind,
    /// Event SAID — final tiebreaker in the canonical sort key.
    pub said: cesr::Digest256,
    /// Branch identity (`None` for pre-divergence shared prefix or non-divergent
    /// IEL; `Some(branch_id)` for a specific post-divergence branch). Branch
    /// identity is determined once at fetch time, not per-comparison.
    pub branch_marker: Option<cesr::Digest256>,
}

impl IelChainPosition {
    /// Compare two positions per IEL canonical chain order.
    ///
    /// - Both pre-divergence (or IEL non-divergent): order by
    ///   `(version ASC, kind sort_priority ASC, said ASC)`.
    /// - One pre-, one post-divergence: pre-divergence comes first
    ///   unconditionally — both branches agree on the pre-divergence prefix.
    /// - Both post-divergence on the same branch (matching `branch_marker`):
    ///   canonical chain order again.
    /// - Both post-divergence on different branches: returns
    ///   [`KelsError::IelDivergent`] — no canonical ordering exists across
    ///   forks.
    pub fn try_cmp(&self, other: &Self) -> Result<Ordering, KelsError> {
        match (&self.branch_marker, &other.branch_marker) {
            (None, None) => Ok(self.canonical_cmp(other)),
            (None, Some(_)) => Ok(Ordering::Less),
            (Some(_), None) => Ok(Ordering::Greater),
            (Some(a), Some(b)) if a == b => Ok(self.canonical_cmp(other)),
            (Some(_), Some(_)) => Err(KelsError::IelDivergent(format!(
                "IelChainPosition comparison crosses divergent IEL branches \
                 (saids {} and {} live on different post-divergence branches)",
                self.said, other.said,
            ))),
        }
    }

    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.version
            .cmp(&other.version)
            .then_with(|| self.kind.sort_priority().cmp(&other.kind.sort_priority()))
            .then_with(|| self.said.cmp(&other.said))
    }
}

/// Cross-chain access into an Identity Event Log, used by the SE verifier and
/// submit handler to resolve `identity_event` bindings on SE chains.
///
/// Implementations must scope every operation to a specific IEL prefix
/// (`identity`) — they reject any SAID whose stored event prefix doesn't
/// match. Mismatch surfaces as [`KelsError::BadIdentityBinding`] (added
/// per #147).
///
/// The trait deliberately omits any SE-chain awareness: a resolver knows
/// only how to look up an IEL event by SAID and how to map that SAID to the
/// (auth_policy, governance_policy) pair the IEL verifier already recorded.
#[async_trait::async_trait]
pub trait IelResolver: Send + Sync {
    /// Fetch a single IEL event by SAID, scoped to `identity`.
    ///
    /// Returns [`KelsError::BadIdentityBinding`] (added per #147) when the
    /// SAID isn't present in the named IEL or when the stored event's
    /// `prefix` doesn't equal `identity`. Other errors propagate as-is from
    /// the storage layer.
    async fn fetch_iel_event(
        &self,
        identity: &cesr::Digest256,
        iel_event_said: &cesr::Digest256,
    ) -> Result<IdentityEvent, KelsError>;

    /// Resolve the `auth_policy` SAID carried at the named IEL event.
    ///
    /// The policy value comes from a SAID-keyed direct lookup against the
    /// IEL's `IelVerification::policy_history` (carry-forward applied at
    /// verification time, not at resolve time).
    ///
    /// **Divergence gate:** returns [`KelsError::IelDivergent`] when the
    /// bound event lives at-or-after the IEL's `first_divergent_version`.
    /// Pre-divergence shared events resolve cleanly even on a divergent IEL.
    async fn resolve_auth_policy_at(
        &self,
        identity: &cesr::Digest256,
        iel_event_said: &cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError>;

    /// Same shape as [`resolve_auth_policy_at`], for `governance_policy`.
    /// Same divergence gate.
    async fn resolve_governance_policy_at(
        &self,
        identity: &cesr::Digest256,
        iel_event_said: &cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError>;

    /// Batch-fetch IEL chain-order positions for a set of SAIDs.
    ///
    /// Used by the SE verifier's monotonic-ratchet check. The verifier
    /// collects every v1+ event's `identity_event` plus each branch's
    /// current `last_identity_event` and calls this once; subsequent
    /// `try_cmp` calls on the returned positions are O(1) hashmap lookups.
    ///
    /// **Errors:** returns [`KelsError::BadIdentityBinding`] when any SAID
    /// in `saids` doesn't resolve in the named IEL or has a prefix
    /// mismatch — the entire call fails (chain-integrity breach).
    async fn iel_chain_positions(
        &self,
        identity: &cesr::Digest256,
        saids: &[cesr::Digest256],
    ) -> Result<HashMap<cesr::Digest256, IelChainPosition>, KelsError>;

    /// Whether the named IEL event passed its IEL auth check AND lives at
    /// `version < first_divergent_version` (or chain non-divergent), per
    /// `IelVerification::is_said_satisfied`.
    ///
    /// Used by the SE verifier (β-ordering: after `resolve_*_at`, before
    /// `is_anchored`) to gate SE bindings. SE chains binding to an IEL event
    /// that didn't pass IEL's verification (Cnt's-own-soft-fail or
    /// post-IEL-divergence soft) are SOFT for terminals / post-SE-divergence
    /// non-terminals, HARD for pre-SE-divergence non-terminals.
    ///
    /// Implementations must scope SAID resolution to `identity` (cross-IEL
    /// contamination surfaces as `BadIdentityBinding`) and must register
    /// the SAID via `IelVerifier::check_satisfied` before walking the IEL
    /// — production impls do this internally from a caller-supplied
    /// `queried_saids` set fixed at construction.
    ///
    /// Returns `false` (not Err) when the SAID is in the IEL's chain but
    /// either (a) failed its auth check, or (b) lives at-or-after the IEL's
    /// `first_divergent_version`. Returns `Err(BadIdentityBinding)` when
    /// the SAID doesn't resolve in the named IEL at all (chain-integrity
    /// breach — caller treats as HARD regardless of position).
    async fn is_satisfied(
        &self,
        identity: &cesr::Digest256,
        said: &cesr::Digest256,
    ) -> Result<bool, KelsError>;

    /// Resolve the IEL prefix that owns the given event SAID. Used by the
    /// `custody.write` verifier (per #167), which holds an IEL event SAID
    /// without prior identity context — this method maps SAID → identity
    /// so subsequent calls (`resolve_auth_policy_at`, `is_satisfied`) can
    /// proceed with the standard identity-scoped surface.
    ///
    /// Returns [`KelsError::BadIdentityBinding`] when the SAID isn't
    /// present in any locally-known IEL. No divergence gate — the caller
    /// applies the existing `resolve_*_at` divergence checks once it has
    /// the identity.
    async fn resolve_identity_for_event(
        &self,
        iel_event_said: &cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError>;

    /// Resolve the **current** `auth_policy` for the named IEL — the
    /// policy adopted at the IEL's tip. Used by the `custody.read`
    /// verifier (per #167), which gates user-facing reads against the
    /// identity-current auth_policy (not a point-in-time pinned policy
    /// like `resolve_auth_policy_at`).
    ///
    /// **Divergence / terminal gates:**
    /// - [`KelsError::IelDivergent`] when the IEL is divergent (no
    ///   canonical "current" policy on a forked chain).
    /// - [`KelsError::ContestedIel`] / [`KelsError::IelDecommissioned`]
    ///   when the chain has reached a terminal state. Caller maps them
    ///   to fail-closed user-facing read responses (403 per #167's
    ///   serve_sad spec).
    /// - [`KelsError::NotFound`] when the IEL prefix isn't locally known
    ///   (the caller maps this to 403 per the same spec).
    async fn resolve_current_auth_policy(
        &self,
        identity: &cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError>;
}
