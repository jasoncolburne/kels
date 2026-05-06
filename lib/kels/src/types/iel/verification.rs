//! Identity Event Log (IEL) verification.
//!
//! Streaming structural + policy verifier for Identity Event Logs. Mirrors
//! `SelVerifier`'s shape: page-by-page processing without holding the full
//! chain in memory; per-branch state for divergent chains; a verification
//! token (`IelVerification`) that proves the chain was fully verified.
//!
//! Per-kind discipline (per `docs/design/iel/events.md §Per-Kind Policy Field
//! Discipline`):
//! - `Icp` — declares both policies; verifier records them as the chain's
//!   tracked auth/governance after immunity + anchoring checks pass.
//! - `Evl` — may carry policies forward unchanged (pure attestation) or evolve
//!   them; the verifier authorizes Evl against the *previous* tracked
//!   governance_policy and immunity-checks any new value before adopting.
//! - `Cnt` / `Dec` — must preserve both policies. The verifier rejects any
//!   change as a structural error (the design's "forbidden field on terminal
//!   kinds" rule, enforced at the verifier rather than at `validate_structure`
//!   because the predecessor's values are needed for the comparison).
//!
//! Soft-fail policy:
//! - Icp anchor check against `event.auth_policy` is **soft** — failure sets
//!   `policy_satisfied=false` but does not abort verification (mirrors SEL Icp).
//! - Evl governance check is **hard** — anchor failure aborts verification.
//! - Cnt/Dec governance check is **soft** — a governance-failed Cnt/Dec sets
//!   `policy_satisfied=false` but the chain's terminal flags
//!   (`is_contested` / `is_decommissioned`) are set unconditionally based on
//!   chain CONTENT (per `docs/design/iel/event-log.md` §"Chain States" —
//!   "at least one Cnt/Dec event in the chain"). Authorization status is
//!   conveyed via `policy_satisfied`. The structural "must preserve policies"
//!   check is still hard.
//! - Immunity violations at Icp or Evl evolution are **hard**.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use verifiable_storage::{Chained, SelfAddressed};

use super::event::{IdentityEvent, IdentityEventKind};
use crate::{AnchorEvaluation, KelsError, types::PolicyChecker};

// ==================== Branch State ====================

/// A verified IEL branch endpoint: tip event plus per-branch policy state.
///
/// Used both as the verifier's runtime state (keyed by tip SAID in a HashMap)
/// and as the per-branch entry in `IelVerification::branches`. One entry on
/// linear chains; two on divergent chains.
#[derive(Debug, Clone)]
pub struct IdentityBranchTip {
    /// The chain head — latest event on this branch.
    pub tip: IdentityEvent,
    /// The effective `auth_policy` for this branch. Seeded from `Icp` and
    /// updated whenever an authorized `Evl` carries a new value.
    pub tracked_auth_policy: cesr::Digest256,
    /// The effective `governance_policy` for this branch. Same semantics.
    pub tracked_governance_policy: cesr::Digest256,
    /// Version of the most recent authorized `Evl` on this branch (the seal).
    /// `None` until the first authorized `Evl`. Cnt/Dec do NOT advance the
    /// seal — they are terminal.
    pub last_governance_version: Option<u64>,
}

// ==================== Verification Token ====================

/// Proof-of-verification token for an Identity Event Log.
///
/// Cannot be constructed outside this crate — only via `IelVerifier`.
/// Carries per-branch tip state plus a SAID-keyed map of every event's
/// declared/tracked `(auth_policy, governance_policy)`. The SAID-keyed map is
/// the data source for `auth_policy_at` and `governance_policy_at`, which
/// SE-side verification (per #147) will use to resolve `identity_event`
/// bindings.
#[derive(Debug, Clone)]
pub struct IelVerification {
    branches: Vec<IdentityBranchTip>,
    policy_history: BTreeMap<cesr::Digest256, (cesr::Digest256, cesr::Digest256)>,
    policy_satisfied: bool,
    diverged_at_version: Option<u64>,
    is_contested: bool,
    is_decommissioned: bool,
    last_governance_version: Option<u64>,
    /// Caller-provided up-front: the IEL event SAIDs the consumer cares about.
    /// Mirrors `KelVerification`'s `queried_saids`. The verifier filters its
    /// satisfaction-tracking to events whose SAID appears here, keeping the
    /// satisfied-set size bounded by caller interest rather than chain size.
    queried_saids: BTreeSet<cesr::Digest256>,
    /// Verifier-populated subset of `queried_saids`: SAIDs whose corresponding
    /// IEL event passed its auth check AND lives at `version <
    /// first_divergent_version` (or the chain is non-divergent). Cnt's-own
    /// auth-pass does not put it in here because Cnt is structurally always
    /// at-or-after the divergence cut. Dec on a clean chain does land here.
    satisfied_saids: BTreeSet<cesr::Digest256>,
}

impl IelVerification {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        branches: Vec<IdentityBranchTip>,
        policy_history: BTreeMap<cesr::Digest256, (cesr::Digest256, cesr::Digest256)>,
        policy_satisfied: bool,
        diverged_at_version: Option<u64>,
        is_contested: bool,
        is_decommissioned: bool,
        last_governance_version: Option<u64>,
        queried_saids: BTreeSet<cesr::Digest256>,
        satisfied_saids: BTreeSet<cesr::Digest256>,
    ) -> Self {
        Self {
            branches,
            policy_history,
            policy_satisfied,
            diverged_at_version,
            is_contested,
            is_decommissioned,
            last_governance_version,
            queried_saids,
            satisfied_saids,
        }
    }

    /// All verified branch endpoints, sorted by tip SAID. Length 1 on linear
    /// chains; 2 on divergent chains. Never empty (the verifier rejects empty
    /// chains at `finish` time).
    pub fn branches(&self) -> &[IdentityBranchTip] {
        &self.branches
    }

    /// The tie-break winner across branches (higher version, then higher kind
    /// `sort_priority`, then lexicographically greater SAID). Returns `None`
    /// when the chain is divergent — callers needing a single tip on a
    /// divergent chain should instead operate on `branches()` explicitly.
    fn winning_branch(&self) -> Option<&IdentityBranchTip> {
        if self.branches.len() != 1 {
            return None;
        }
        self.branches.first()
    }

    /// The latest verified event on a non-divergent chain. `None` when divergent.
    pub fn current_event(&self) -> Option<&IdentityEvent> {
        self.winning_branch().map(|b| &b.tip)
    }

    /// The IEL prefix. All branches share the same prefix; returns the first
    /// branch's prefix (verifier enforces consistency on every event).
    #[allow(clippy::expect_used)]
    pub fn prefix(&self) -> &cesr::Digest256 {
        // Verifier::finish rejects empty `branches`; this is total.
        &self
            .branches
            .first()
            .expect("IelVerification invariant: branches is non-empty")
            .tip
            .prefix
    }

    /// The chain's topic. All branches share the same topic.
    #[allow(clippy::expect_used)]
    pub fn topic(&self) -> &str {
        &self
            .branches
            .first()
            .expect("IelVerification invariant: branches is non-empty")
            .tip
            .topic
    }

    /// The lowest version at which divergence was first observed.
    pub fn diverged_at_version(&self) -> Option<u64> {
        self.diverged_at_version
    }

    /// Convenience: true when more than one branch tip exists.
    pub fn is_divergent(&self) -> bool {
        self.branches.len() > 1
    }

    /// True when at least one `Cnt` event is in the chain. Reflects chain
    /// CONTENT per `docs/design/iel/event-log.md` §"Chain States" — set
    /// unconditionally on any landed `Cnt`, regardless of whether its
    /// governance check passed. Authorization status is in `policy_satisfied`.
    pub fn is_contested(&self) -> bool {
        self.is_contested
    }

    /// True when at least one `Dec` event is in the chain. Same content-based
    /// semantics as `is_contested`.
    pub fn is_decommissioned(&self) -> bool {
        self.is_decommissioned
    }

    /// Version of the most recent authorized `Evl` (the evaluation seal),
    /// taken across branches.
    pub fn last_governance_version(&self) -> Option<u64> {
        self.last_governance_version
    }

    /// Whether all per-event anchor / soft checks passed. Chain-wide signal.
    pub fn policy_satisfied(&self) -> bool {
        self.policy_satisfied
    }

    /// The `auth_policy` declared (at Icp) or evolved/preserved (at Evl/Cnt/Dec)
    /// at the named IEL event. Returns `None` if the SAID is not in this chain.
    ///
    /// **Verifier-view, not raw-event-view.** The returned policy reflects
    /// what the verifier *adopted* into branch state when it walked the
    /// chain — which can diverge from what the event itself declares in
    /// the rare case of a post-divergence Evl that auth-failed (#147
    /// post-divergence soft-fail propagation). For such an event the
    /// verifier records prior tracked policies (the unauthenticated
    /// evolution is not adopted) even though the event payload declares
    /// the new values. Consumers should treat this accessor's answer as
    /// authoritative; reading `event.auth_policy` directly bypasses the
    /// verifier's trust contract.
    pub fn auth_policy_at(&self, said: &cesr::Digest256) -> Option<cesr::Digest256> {
        self.policy_history.get(said).map(|(a, _)| *a)
    }

    /// Same as [`auth_policy_at`], for `governance_policy`. Same
    /// verifier-view-not-raw-event-view caveat applies.
    pub fn governance_policy_at(&self, said: &cesr::Digest256) -> Option<cesr::Digest256> {
        self.policy_history.get(said).map(|(_, g)| *g)
    }

    /// Whether the named IEL event passed its auth check AND lives at
    /// `version < first_divergent_version` (or the chain is non-divergent).
    /// Mirrors `KelVerification::is_said_anchored`. Used by SE verification
    /// to gate `identity_event` bindings. Returns `false` for SAIDs not in
    /// `queried_saids` — callers must register interest before walking.
    pub fn is_said_satisfied(&self, said: &cesr::Digest256) -> bool {
        self.satisfied_saids.contains(said)
    }

    /// The full set of satisfied SAIDs (subset of `queried_saids`).
    pub fn satisfied_saids(&self) -> &BTreeSet<cesr::Digest256> {
        &self.satisfied_saids
    }

    /// The set of SAIDs the caller registered interest in.
    pub fn queried_saids(&self) -> &BTreeSet<cesr::Digest256> {
        &self.queried_saids
    }

    /// Stamp a server-reported divergence version. Crate-private; only the
    /// builder layer should call this when the local verifier did not directly
    /// observe a fork that the server did. (First consumer lands in Gap 6.)
    #[allow(dead_code)]
    pub(crate) fn set_diverged_at_version(&mut self, version: u64) {
        if self.diverged_at_version.is_none() {
            self.diverged_at_version = Some(version);
        }
    }
}

// ==================== Streaming Verifier ====================

/// Streaming structural + policy verifier for Identity Event Logs.
///
/// Mirrors `SelVerifier`. Tracks per-branch state in a HashMap keyed by tip
/// SAID; processes events page by page; produces `IelVerification` on
/// `finish`. `resume` re-hydrates from a prior token.
pub struct IelVerifier {
    prefix: Option<cesr::Digest256>,
    topic: Option<String>,
    branches: HashMap<cesr::Digest256, IdentityBranchTip>,
    policy_history: BTreeMap<cesr::Digest256, (cesr::Digest256, cesr::Digest256)>,
    generation_buffer: Vec<IdentityEvent>,
    current_generation_version: Option<u64>,
    saw_any_events: bool,
    policy_satisfied: bool,
    diverged_at_version: Option<u64>,
    is_contested: bool,
    is_decommissioned: bool,
    queried_saids: BTreeSet<cesr::Digest256>,
    satisfied_saids: BTreeSet<cesr::Digest256>,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    /// #156 collect-mode: when `true`, deferrable failures
    /// (`MissingKelAnchor`) accumulate into `deferred_failures` and the
    /// walk treats them as soft-fail-style; when `false`, deferrables
    /// propagate as `Err(KelsError)` and halt the walk (legacy behavior).
    /// Permanent failures always halt.
    collecting: bool,
    /// #156: accumulated deferrable failures. Empty in strict mode.
    deferred_failures: Vec<crate::DeferredFailure>,
}

impl IelVerifier {
    pub fn new(
        prefix: Option<&cesr::Digest256>,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
    ) -> Self {
        Self {
            prefix: prefix.copied(),
            topic: None,
            branches: HashMap::new(),
            policy_history: BTreeMap::new(),
            generation_buffer: Vec::new(),
            current_generation_version: None,
            saw_any_events: false,
            policy_satisfied: true,
            diverged_at_version: None,
            is_contested: false,
            is_decommissioned: false,
            queried_saids: BTreeSet::new(),
            satisfied_saids: BTreeSet::new(),
            checker,
            collecting: false,
            deferred_failures: Vec::new(),
        }
    }

    /// Enable #156 collect-mode for this verifier. Deferrable failures
    /// (`MissingKelAnchor`) accumulate instead of halting the walk.
    /// Permanent failures still halt. Idempotent.
    pub fn enable_collecting(&mut self) -> &mut Self {
        self.collecting = true;
        self
    }

    /// Read accumulated deferrable failures (after running
    /// `verify_page_collecting`). Empty in strict mode.
    pub fn deferred_failures(&self) -> &[crate::DeferredFailure] {
        &self.deferred_failures
    }

    /// Register IEL event SAIDs the caller cares about for satisfaction
    /// tracking. Mirrors `KelVerifier::check_anchors`. Call before
    /// `verify_page` (or before resuming the walk via `resume`). Repeated
    /// calls union the sets — they don't replace.
    ///
    /// During the walk, for each event whose SAID is in `queried_saids`: the
    /// verifier adds the SAID to `satisfied_saids` iff the event passed its
    /// auth check AND lives at `version < first_divergent_version` (or chain
    /// is non-divergent).
    pub fn check_satisfied(
        &mut self,
        saids: impl IntoIterator<Item = cesr::Digest256>,
    ) -> &mut Self {
        self.queried_saids.extend(saids);
        self
    }

    /// Re-hydrate a verifier from a prior verification token. Subsequent
    /// `verify_page` calls extend the same per-branch state.
    ///
    /// Unlike `KelVerifier::resume` (which resets queried/anchored), the IEL
    /// path rehydrates `queried_saids` and `satisfied_saids` from the prior
    /// token. SE-driven multi-page verification needs the caller's registered
    /// interest to persist across page boundaries; resetting would force the
    /// caller to re-register on every resume, which conflicts with the
    /// streaming pre-walk pattern where the queried set is collected once
    /// upfront. KEL's symmetric fix is deferred to #161.
    pub fn resume(
        verification: &IelVerification,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
    ) -> Result<Self, KelsError> {
        let mut branches: HashMap<cesr::Digest256, IdentityBranchTip> = HashMap::new();
        for branch in verification.branches() {
            branches.insert(branch.tip.said, branch.clone());
        }

        let prefix = *verification.prefix();
        let topic = verification.topic().to_string();

        Ok(Self {
            prefix: Some(prefix),
            topic: Some(topic),
            branches,
            policy_history: verification.policy_history.clone(),
            generation_buffer: Vec::new(),
            current_generation_version: None,
            saw_any_events: true,
            policy_satisfied: verification.policy_satisfied(),
            diverged_at_version: verification.diverged_at_version(),
            is_contested: verification.is_contested(),
            is_decommissioned: verification.is_decommissioned(),
            queried_saids: verification.queried_saids.clone(),
            satisfied_saids: verification.satisfied_saids.clone(),
            checker,
            collecting: false,
            deferred_failures: Vec::new(),
        })
    }

    pub fn is_divergent(&self) -> bool {
        self.branches.len() > 1
    }

    /// Verify a single event's SAID, prefix, and topic continuity. Per-kind
    /// validation and chain-state advancement happens in `flush_generation`.
    fn verify_event(&self, event: &IdentityEvent) -> Result<(), KelsError> {
        event.verify_said()?;

        if let Some(ref expected) = self.prefix
            && event.prefix != *expected
        {
            return Err(KelsError::VerificationFailed(format!(
                "IEL event {} prefix {} doesn't match IEL prefix {}",
                event.said, event.prefix, expected
            )));
        }

        if let Some(ref expected) = self.topic
            && event.topic != *expected
        {
            return Err(KelsError::VerificationFailed(format!(
                "IEL event {} topic {} doesn't match IEL topic {}",
                event.said, event.topic, expected
            )));
        }

        Ok(())
    }

    /// #156 Gap-8: invoke `checker.is_immune` with collect-mode awareness.
    /// In collect mode, [`KelsError::MissingSadObject`] (the policy SAD
    /// object hasn't propagated locally yet) accumulates as a deferrable
    /// failure and reports phantom-immune (`true`) so the verifier walk
    /// continues without halting; the chain commit is gated by the
    /// handler's emptiness check on `deferred_failures`. In strict mode
    /// the error propagates as before. Non-`MissingSadObject` errors
    /// always propagate.
    async fn is_immune_collecting(&mut self, policy: &cesr::Digest256) -> Result<bool, KelsError> {
        match self.checker.is_immune(policy).await {
            Ok(b) => Ok(b),
            Err(KelsError::MissingSadObject(missing)) if self.collecting => {
                self.deferred_failures
                    .push(crate::DeferredFailure::missing_sad_object(missing.said));
                self.policy_satisfied = false;
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    /// #156 Gap-8: invoke `checker.evaluate` with collect-mode awareness.
    /// On [`KelsError::MissingSadObject`] in collect mode, accumulate the
    /// deferrable failure and synthesize a satisfied-but-flagged
    /// `AnchorEvaluation` so the verifier walk continues. `policy_satisfied=false`
    /// flags the chain; non-empty `deferred_failures` drives the 422
    /// handler response.
    async fn evaluate_collecting(
        &mut self,
        said: &cesr::Digest256,
        policy: &cesr::Digest256,
    ) -> Result<AnchorEvaluation, KelsError> {
        match self.checker.evaluate(said, policy).await {
            Ok(eval) => Ok(eval),
            Err(KelsError::MissingSadObject(missing)) if self.collecting => {
                self.deferred_failures
                    .push(crate::DeferredFailure::missing_sad_object(missing.said));
                self.policy_satisfied = false;
                Ok(AnchorEvaluation {
                    satisfied: true,
                    missing_anchors: Vec::new(),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Process all events at the current generation (same version).
    async fn flush_generation(&mut self) -> Result<(), KelsError> {
        let events = std::mem::take(&mut self.generation_buffer);
        let version = match self.current_generation_version.take() {
            Some(v) => v,
            None => return Ok(()),
        };

        if events.is_empty() {
            return Ok(());
        }

        // Structural validation first
        for event in &events {
            event
                .validate_structure()
                .map_err(KelsError::VerificationFailed)?;
        }

        if self.branches.is_empty() {
            // First generation — must be a single Icp at v0.
            if events.len() != 1 {
                return Err(KelsError::VerificationFailed(
                    "Multiple events at version 0 — IEL v0 divergence is not permitted".into(),
                ));
            }
            let event = &events[0];
            if version != 0 {
                return Err(KelsError::VerificationFailed(format!(
                    "First IEL generation must be at version 0, got {}",
                    version
                )));
            }
            event.verify_prefix()?;

            // Hard immunity check on both declared policies (per design).
            // #156 Gap-8: in collect mode, `KelsError::MissingSadObject`
            // (policy SAD not yet local) accumulates as deferrable + the
            // immunity check is treated as satisfied for verifier-walk
            // purposes (`policy_satisfied=false` flags the chain;
            // deferred_failures non-empty drives the handler 422).
            if !self.is_immune_collecting(&event.auth_policy).await? {
                return Err(KelsError::VerificationFailed(format!(
                    "IEL Icp {} declares non-immune auth_policy {}",
                    event.said, event.auth_policy
                )));
            }
            if !self.is_immune_collecting(&event.governance_policy).await? {
                return Err(KelsError::VerificationFailed(format!(
                    "IEL Icp {} declares non-immune governance_policy {}",
                    event.said, event.governance_policy
                )));
            }

            // Soft anchor check — Icp self-authorization. Failure leaves the
            // chain in `policy_satisfied=false` but does not abort.
            // Collect-mode (#156): accumulate any `missing_anchors` as
            // deferrable failures. The event still lands either way.
            let icp_evaluation = self
                .evaluate_collecting(&event.said, &event.auth_policy)
                .await?;
            if !icp_evaluation.satisfied {
                self.policy_satisfied = false;
                if self.collecting {
                    for kel_prefix in &icp_evaluation.missing_anchors {
                        self.deferred_failures
                            .push(crate::DeferredFailure::missing_kel_anchor(
                                *kel_prefix,
                                event.said,
                            ));
                    }
                }
            }

            self.branches.insert(
                event.said,
                IdentityBranchTip {
                    tip: event.clone(),
                    tracked_auth_policy: event.auth_policy,
                    tracked_governance_policy: event.governance_policy,
                    last_governance_version: None,
                },
            );
            self.policy_history
                .insert(event.said, (event.auth_policy, event.governance_policy));

            // Satisfied-saids tracking. Icp at v=0 is structurally
            // pre-divergence (divergence is detected at v>=1 when a
            // generation has 2+ events).
            if icp_evaluation.satisfied && self.queried_saids.contains(&event.said) {
                self.satisfied_saids.insert(event.said);
            }

            if self.prefix.is_none() {
                self.prefix = Some(event.prefix);
            }
            return Ok(());
        }

        // Max 2 events per generation post-Icp (one per branch).
        if events.len() > 2 {
            return Err(KelsError::VerificationFailed(format!(
                "IEL generation at version {} has {} events, max 2 allowed",
                version,
                events.len()
            )));
        }

        // Detect divergence: more events than branches means a fork.
        if events.len() > self.branches.len() && self.diverged_at_version.is_none() {
            self.diverged_at_version = Some(version);
        }

        let mut new_branches: HashMap<cesr::Digest256, IdentityBranchTip> = HashMap::new();

        for event in &events {
            let previous = event.previous.as_ref().ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "Non-inception IEL event {} has no previous event",
                    event.said
                ))
            })?;

            // Clone branch state out before invoking `&mut self` helpers
            // (`evaluate_collecting` / `is_immune_collecting`) — the
            // immutable borrow of `self.branches` from `.get(previous)`
            // would otherwise conflict with the mutable borrow inside
            // those helpers.
            let branch = self
                .branches
                .get(previous)
                .ok_or_else(|| {
                    KelsError::VerificationFailed(format!(
                        "IEL event {} previous {} does not match any branch tip",
                        event.said, previous
                    ))
                })?
                .clone();

            // #171 divergent-chain gate (per-event): once an IEL is
            // divergent, post-divergence events are restricted to {Cnt}
            // — IEL has no Rpr; divergence = compromise; Cnt is the
            // owner's testimony "this IEL is no longer authoritative."
            // The divergence-creating events themselves (at version ==
            // diverged_at_version) bypass this check; only events at
            // version > diverged_at_version are post-divergence. See
            // `docs/design/iel/event-log.md §Compromise Posture and
            // Trust Layer`.
            if let Some(div_at) = self.diverged_at_version
                && event.version > div_at
                && event.kind != IdentityEventKind::Cnt
            {
                return Err(KelsError::VerificationFailed(format!(
                    "IEL event {} ({}) cannot extend divergent chain at version {} \
                     (only Cnt allowed post-divergence)",
                    event.said, event.kind, event.version
                )));
            }

            // #171 terminal-state gate: `Cnt` and `Dec` are tombstones —
            // extending either tip is structurally invalid. Cnt-supersedes-
            // Dec (Cnt forking from a pre-Dec ancestor) requires non-tip
            // parent-lookup and is deferred to #174; until then post-Dec
            // rejects all submissions including Cnt. Per-branch (not
            // chain-wide). See `docs/design/iel/event-log.md §Chain States`.
            if branch.tip.kind.is_terminal() {
                return Err(KelsError::VerificationFailed(format!(
                    "IEL event {} cannot extend terminal {} {}",
                    event.said, branch.tip.kind, branch.tip.said
                )));
            }

            let expected_version = branch.tip.version + 1;
            if event.version != expected_version {
                return Err(KelsError::VerificationFailed(format!(
                    "IEL event {} has version {} but expected {} (branch tip + 1)",
                    event.said, event.version, expected_version
                )));
            }

            // Anchor check against the branch's tracked governance_policy.
            // Pre-divergence Evl: hard-fail (advancement event must be authorized).
            // Pre-divergence Cnt/Dec: soft-fail (terminal flags content-based;
            // auth status surfaces via `policy_satisfied`) per
            // `docs/design/iel/event-log.md` §"Chain States".
            // Post-divergence (event.version >= diverged_at_version): all
            // auth-check failures convert to soft (the chain is already
            // contested-by-construction; further failures don't add information,
            // and bouncing the verification would lose pre-divergence reads).
            // Structural integrity rules (immunity, content preservation) stay
            // hard regardless of position — Cnt doesn't change well-formedness.
            let governance_evaluation = self
                .evaluate_collecting(&event.said, &branch.tracked_governance_policy)
                .await?;
            let governance_satisfied = governance_evaluation.satisfied;
            let post_divergence = self.diverged_at_version.is_some_and(|d| event.version >= d);

            match event.kind {
                IdentityEventKind::Icp => {
                    return Err(KelsError::VerificationFailed(format!(
                        "IEL Icp event {} at version {} — Icp must be at v0",
                        event.said, event.version
                    )));
                }
                IdentityEventKind::Evl => {
                    if !governance_satisfied && !post_divergence {
                        // Collect-mode (#156): if the policy could be
                        // satisfied by a missing anchor's commitment,
                        // accumulate each as deferrable and soft-fail-style
                        // continue (treat as post-divergence-soft would —
                        // event lands, prior tracked state preserved). The
                        // empty-`missing_anchors` case (permanently
                        // unsatisfiable) falls through to the hard path.
                        if self.collecting && !governance_evaluation.missing_anchors.is_empty() {
                            for kel_prefix in &governance_evaluation.missing_anchors {
                                self.deferred_failures.push(
                                    crate::DeferredFailure::missing_kel_anchor(
                                        *kel_prefix,
                                        event.said,
                                    ),
                                );
                            }
                            self.policy_satisfied = false;
                        } else {
                            return Err(KelsError::VerificationFailed(format!(
                                "IEL Evl {} not anchored under tracked governance_policy {}",
                                event.said, branch.tracked_governance_policy
                            )));
                        }
                    } else if !governance_satisfied {
                        // Post-divergence soft path: chain-wide flag flipped;
                        // event still lands but its evolved policies are NOT
                        // adopted (the auth chain that would have authorized
                        // the evolution failed). Tracked state preserves
                        // prior, seal does not advance.
                        self.policy_satisfied = false;
                    }

                    // Per-kind discipline: Evl may evolve policies. Check
                    // immunity on any new value before adopting it. Hard
                    // even on post-divergence: structural well-formedness
                    // is independent of divergence position.
                    let auth_changed = event.auth_policy != branch.tracked_auth_policy;
                    let gov_changed = event.governance_policy != branch.tracked_governance_policy;

                    if auth_changed && !self.is_immune_collecting(&event.auth_policy).await? {
                        return Err(KelsError::VerificationFailed(format!(
                            "IEL Evl {} evolves auth_policy to non-immune {}",
                            event.said, event.auth_policy
                        )));
                    }
                    if gov_changed && !self.is_immune_collecting(&event.governance_policy).await? {
                        return Err(KelsError::VerificationFailed(format!(
                            "IEL Evl {} evolves governance_policy to non-immune {}",
                            event.said, event.governance_policy
                        )));
                    }

                    let (track_auth, track_gov, last_gov) = if governance_satisfied {
                        (
                            event.auth_policy,
                            event.governance_policy,
                            Some(event.version),
                        )
                    } else {
                        (
                            branch.tracked_auth_policy,
                            branch.tracked_governance_policy,
                            branch.last_governance_version,
                        )
                    };

                    new_branches.insert(
                        event.said,
                        IdentityBranchTip {
                            tip: event.clone(),
                            tracked_auth_policy: track_auth,
                            tracked_governance_policy: track_gov,
                            last_governance_version: last_gov,
                        },
                    );
                    self.policy_history
                        .insert(event.said, (track_auth, track_gov));
                }
                IdentityEventKind::Cnt | IdentityEventKind::Dec => {
                    // Hard structural rule: Cnt/Dec must preserve both policies.
                    if event.auth_policy != branch.tracked_auth_policy {
                        return Err(KelsError::VerificationFailed(format!(
                            "IEL {} event {} must preserve auth_policy (got {}, expected {})",
                            event.kind, event.said, event.auth_policy, branch.tracked_auth_policy
                        )));
                    }
                    if event.governance_policy != branch.tracked_governance_policy {
                        return Err(KelsError::VerificationFailed(format!(
                            "IEL {} event {} must preserve governance_policy (got {}, expected {})",
                            event.kind,
                            event.said,
                            event.governance_policy,
                            branch.tracked_governance_policy
                        )));
                    }

                    // Terminal flags reflect chain CONTENT (any Cnt/Dec event
                    // sets them) per `docs/design/iel/event-log.md` §"Chain
                    // States". Authorization status is conveyed separately via
                    // `policy_satisfied` so SE consumers reading the
                    // verification token see "this chain is terminated" even
                    // when the terminating event was governance-failed at
                    // verification time.
                    if event.kind.is_contest() {
                        self.is_contested = true;
                    } else {
                        self.is_decommissioned = true;
                    }
                    if !governance_satisfied {
                        self.policy_satisfied = false;
                        if self.collecting {
                            for kel_prefix in &governance_evaluation.missing_anchors {
                                self.deferred_failures.push(
                                    crate::DeferredFailure::missing_kel_anchor(
                                        *kel_prefix,
                                        event.said,
                                    ),
                                );
                            }
                        }
                    }

                    new_branches.insert(
                        event.said,
                        IdentityBranchTip {
                            tip: event.clone(),
                            tracked_auth_policy: branch.tracked_auth_policy,
                            tracked_governance_policy: branch.tracked_governance_policy,
                            // Cnt/Dec are terminal; they do not advance the seal.
                            last_governance_version: branch.last_governance_version,
                        },
                    );
                    self.policy_history.insert(
                        event.said,
                        (branch.tracked_auth_policy, branch.tracked_governance_policy),
                    );
                }
            }

            // Satisfied-SAIDs tracking. Predicate: SAID was queried, the
            // event passed its auth check, AND the event lives at
            // `version < first_divergent_version` (or chain non-divergent).
            // Cnt is structurally always at-or-after divergence (Cnt creates
            // it), so Cnt is never in `satisfied_saids` even when its own
            // governance check passed. Dec on a clean chain CAN be satisfied.
            if !post_divergence && governance_satisfied && self.queried_saids.contains(&event.said)
            {
                self.satisfied_saids.insert(event.said);
            }
        }

        // Carry forward branches that no event in this generation extended.
        for (said, state) in &self.branches {
            if !events.iter().any(|e| e.previous.as_ref() == Some(said)) {
                new_branches.insert(*said, state.clone());
            }
        }

        self.branches = new_branches;
        Ok(())
    }

    /// #156 collect-mode sibling of [`verify_page`]. Equivalent to
    /// enabling collecting + calling `verify_page`. Deferrable failures
    /// (`MissingKelAnchor`) accumulate into the verifier's internal
    /// buffer (read via [`deferred_failures`]) and the walk soft-fails
    /// the affected events; permanent failures still halt with
    /// `Err(KelsError)`.
    pub async fn verify_page_collecting(
        &mut self,
        events: &[IdentityEvent],
    ) -> Result<(), KelsError> {
        self.collecting = true;
        self.verify_page(events).await
    }

    /// #156 collect-mode sibling of [`finish`]. Returns the verification
    /// token alongside the accumulated deferrable failures.
    pub async fn finish_collecting(
        mut self,
    ) -> Result<(IelVerification, Vec<crate::DeferredFailure>), KelsError> {
        self.collecting = true;
        self.finish_internal().await
    }

    /// Shared finalization. See `SelVerifier::finish_internal` for the
    /// ordering rationale (flush before take so any deferred failures
    /// pushed during the final flush land in the returned vec).
    async fn finish_internal(
        mut self,
    ) -> Result<(IelVerification, Vec<crate::DeferredFailure>), KelsError> {
        self.flush_generation().await?;
        let deferred = std::mem::take(&mut self.deferred_failures);

        if !self.saw_any_events {
            return Err(KelsError::VerificationFailed("Empty IEL".into()));
        }
        if self.branches.is_empty() {
            return Err(KelsError::VerificationFailed(
                "No tip after IEL verification".into(),
            ));
        }

        let mut branches: Vec<IdentityBranchTip> = self.branches.into_values().collect();
        branches.sort_by_key(|b| b.tip.said);

        let last_governance_version = branches
            .iter()
            .filter_map(|b| b.last_governance_version)
            .max();

        Ok((
            IelVerification::new(
                branches,
                self.policy_history,
                self.policy_satisfied,
                self.diverged_at_version,
                self.is_contested,
                self.is_decommissioned,
                last_governance_version,
                self.queried_saids,
                self.satisfied_saids,
            ),
            deferred,
        ))
    }

    /// Verify a page of events. Events must arrive in
    /// `(version ASC, kind sort_priority ASC, said ASC)` order with complete
    /// generations within the page.
    pub async fn verify_page(&mut self, events: &[IdentityEvent]) -> Result<(), KelsError> {
        for event in events {
            self.saw_any_events = true;

            self.verify_event(event)?;

            if self.topic.is_none() {
                self.topic = Some(event.topic.clone());
            }

            if let Some(current_version) = self.current_generation_version
                && event.version != current_version
            {
                self.flush_generation().await?;
            }

            self.current_generation_version = Some(event.version);
            self.generation_buffer.push(event.clone());
        }
        Ok(())
    }

    /// Finish verification and produce the proof token. Strict-mode
    /// callers ignore any deferrable accumulator (they shouldn't have
    /// any, since strict-mode halts on the first deferrable).
    pub async fn finish(self) -> Result<IelVerification, KelsError> {
        let (verification, _deferred) = self.finish_internal().await?;
        Ok(verification)
    }
}

// ==================== Tests ====================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::AnchorEvaluation;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    const TEST_TOPIC: &str = "kels/iel/v1/identity/test";

    fn pass() -> AnchorEvaluation {
        AnchorEvaluation {
            satisfied: true,
            missing_anchors: Vec::new(),
        }
    }

    fn fail() -> AnchorEvaluation {
        AnchorEvaluation {
            satisfied: false,
            missing_anchors: Vec::new(),
        }
    }

    /// Test fake: every (said, policy) anchor passes; every policy is immune.
    struct AlwaysPassChecker;

    #[async_trait::async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn evaluate(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<AnchorEvaluation, KelsError> {
            Ok(pass())
        }
        async fn is_immune(&self, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    /// Test fake: every anchor fails; every policy is immune. Useful for
    /// exercising soft / hard anchor-fail paths.
    struct AnchorRejectChecker;

    #[async_trait::async_trait]
    impl PolicyChecker for AnchorRejectChecker {
        async fn evaluate(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<AnchorEvaluation, KelsError> {
            Ok(fail())
        }
        async fn is_immune(&self, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    /// Test fake: anchor passes; only one specific policy SAID is immune.
    /// Lets a test pin "introduce non-immune policy at Icp/Evl is rejected."
    struct ImmuneOnlyForChecker {
        immune: cesr::Digest256,
    }

    #[async_trait::async_trait]
    impl PolicyChecker for ImmuneOnlyForChecker {
        async fn evaluate(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<AnchorEvaluation, KelsError> {
            Ok(pass())
        }
        async fn is_immune(&self, policy: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(*policy == self.immune)
        }
    }

    /// Test fake: anchor passes; an explicit set of policies is immune.
    /// Lets a test pin "evolution to a non-immune policy at Evl is rejected."
    struct ImmuneSetChecker {
        immune: Vec<cesr::Digest256>,
    }

    #[async_trait::async_trait]
    impl PolicyChecker for ImmuneSetChecker {
        async fn evaluate(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<AnchorEvaluation, KelsError> {
            Ok(pass())
        }
        async fn is_immune(&self, policy: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(self.immune.contains(policy))
        }
    }

    fn always_pass() -> Arc<dyn PolicyChecker + Send + Sync> {
        Arc::new(AlwaysPassChecker)
    }

    /// Helper: run `verify_page` then `finish` and return the first error
    /// encountered, or the final token. Lets tests use a single `?` flow
    /// instead of chaining `.err().or_else(...)` across `await` boundaries
    /// (which doesn't compile because closures aren't async).
    async fn run(
        mut verifier: IelVerifier,
        events: &[IdentityEvent],
    ) -> Result<IelVerification, KelsError> {
        verifier.verify_page(events).await?;
        verifier.finish().await
    }

    // ---------- #156 collect-mode ----------

    /// Collect-mode: an Evl whose anchor evaluation reports a non-empty
    /// `missing_anchors` list accumulates one `DeferredFailure::MissingKelAnchor`
    /// per missing endorser instead of halting at the hard governance gate.
    /// The chain advances soft-fail-style (event lands; prior tracked
    /// policies preserved; chain-wide `policy_satisfied=false`).
    #[tokio::test]
    async fn collect_mode_evl_accumulates_missing_kel_anchor() {
        use crate::DeferredFailure;

        struct MissingAnchorChecker {
            kel_prefix: cesr::Digest256,
        }
        #[async_trait::async_trait]
        impl PolicyChecker for MissingAnchorChecker {
            async fn evaluate(
                &self,
                _: &cesr::Digest256,
                _: &cesr::Digest256,
            ) -> Result<AnchorEvaluation, KelsError> {
                Ok(AnchorEvaluation {
                    satisfied: false,
                    missing_anchors: vec![self.kel_prefix],
                })
            }
            async fn is_immune(&self, _: &cesr::Digest256) -> Result<bool, KelsError> {
                Ok(true)
            }
        }

        let auth = test_digest(b"auth-collect-iel");
        let gov = test_digest(b"gov-collect-iel");
        let kel_prefix = test_digest(b"missing-kel-prefix-iel");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();
        let v1_said = v1.said;

        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(MissingAnchorChecker { kel_prefix });
        let mut verifier = IelVerifier::new(Some(&v0.prefix), checker);
        verifier
            .verify_page_collecting(&[v0, v1])
            .await
            .expect("collect-mode does not halt on missing anchor");
        let (verification, deferred) = verifier.finish_collecting().await.unwrap();

        // Two entries: Icp self-anchor missing (soft already in strict mode)
        // + Evl governance missing (would have been hard in strict mode).
        assert_eq!(deferred.len(), 2);
        assert!(deferred.iter().any(|d| matches!(
            d,
            DeferredFailure::MissingKelAnchor(dep)
                if dep.kel_prefix == kel_prefix && dep.anchor_said == v1_said
        )));
        assert!(!verification.policy_satisfied());
    }

    /// Collect-mode (#156 Gap-8): when `checker.evaluate` or `is_immune`
    /// returns `KelsError::MissingSadObject` (the policy SAD object
    /// hasn't propagated locally), the IEL verifier accumulates a
    /// `DeferredFailure::MissingSadObject` and continues the walk
    /// soft-fail-style. Strict mode would halt; collect mode lets the
    /// handler emit a typed-422 with `sad_object` deps.
    #[tokio::test]
    async fn collect_mode_evl_accumulates_missing_sad_object() {
        use crate::DeferredFailure;

        struct MissingSadObjectChecker {
            policy: cesr::Digest256,
        }
        #[async_trait::async_trait]
        impl PolicyChecker for MissingSadObjectChecker {
            async fn evaluate(
                &self,
                _: &cesr::Digest256,
                policy: &cesr::Digest256,
            ) -> Result<AnchorEvaluation, KelsError> {
                if *policy == self.policy {
                    Err(KelsError::missing_sad_object(*policy))
                } else {
                    Ok(AnchorEvaluation {
                        satisfied: true,
                        missing_anchors: Vec::new(),
                    })
                }
            }
            async fn is_immune(&self, _: &cesr::Digest256) -> Result<bool, KelsError> {
                Ok(true)
            }
        }

        let auth = test_digest(b"auth-sad-collect");
        let gov = test_digest(b"gov-sad-collect");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();

        // Pin the auth_policy SAID as the missing one so both the Icp
        // self-anchor evaluate (`event.auth_policy`) and the Evl
        // governance gate (`branch.tracked_governance_policy = gov`) get
        // exercised — Evl checks gov, which IS local, so the missing dep
        // surfaces specifically at the Icp evaluate call.
        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(MissingSadObjectChecker { policy: auth });
        let mut verifier = IelVerifier::new(Some(&v0.prefix), checker);
        verifier
            .verify_page_collecting(&[v0, v1])
            .await
            .expect("collect-mode does not halt on missing SAD object");
        let (verification, deferred) = verifier.finish_collecting().await.unwrap();

        assert!(deferred.iter().any(|d| matches!(
            d,
            DeferredFailure::MissingSadObject(dep) if dep.said == auth
        )));
        assert!(!verification.policy_satisfied());
    }

    /// Strict-mode counterpart: `KelsError::MissingSadObject` from the
    /// checker propagates as Err, halting the walk. Collect-mode
    /// behavior must not bleed through `verify_page` (without the
    /// `_collecting` variant). Icp processing happens in
    /// `flush_generation`, which triggers at `finish()` for a
    /// single-generation page.
    #[tokio::test]
    async fn strict_mode_halts_on_missing_sad_object() {
        struct MissingSadObjectChecker;
        #[async_trait::async_trait]
        impl PolicyChecker for MissingSadObjectChecker {
            async fn evaluate(
                &self,
                _: &cesr::Digest256,
                policy: &cesr::Digest256,
            ) -> Result<AnchorEvaluation, KelsError> {
                Err(KelsError::missing_sad_object(*policy))
            }
            async fn is_immune(&self, _: &cesr::Digest256) -> Result<bool, KelsError> {
                Ok(true)
            }
        }

        let auth = test_digest(b"auth-sad-strict");
        let gov = test_digest(b"gov-sad-strict");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(MissingSadObjectChecker);
        let mut verifier = IelVerifier::new(Some(&v0.prefix), checker);
        verifier.verify_page(&[v0]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            matches!(err, KelsError::MissingSadObject(_)),
            "expected MissingSadObject, got {err:?}"
        );
    }

    // ---------- Linear chain ----------

    #[tokio::test]
    async fn linear_chain_icp_then_evl_verifies() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert_eq!(v.branches().len(), 1);
        assert!(!v.is_divergent());
        assert!(v.policy_satisfied());
        assert_eq!(v.last_governance_version(), Some(1));
        assert_eq!(v.current_event().map(|e| e.said), Some(v1.said));
        assert_eq!(v.auth_policy_at(&v0.said), Some(auth));
        assert_eq!(v.governance_policy_at(&v0.said), Some(gov));
        assert_eq!(v.auth_policy_at(&v1.said), Some(auth)); // unchanged
    }

    #[tokio::test]
    async fn evl_evolves_auth_policy_visible_in_history() {
        let auth1 = test_digest(b"auth-1");
        let auth2 = test_digest(b"auth-2");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth1, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, Some(auth2), None).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert_eq!(v.auth_policy_at(&v0.said), Some(auth1));
        assert_eq!(v.auth_policy_at(&v1.said), Some(auth2));
        assert_eq!(v.governance_policy_at(&v0.said), Some(gov));
        assert_eq!(v.governance_policy_at(&v1.said), Some(gov));
    }

    #[tokio::test]
    async fn empty_chain_rejected() {
        let verifier = IelVerifier::new(Some(&test_digest(b"empty")), always_pass());
        assert!(verifier.finish().await.is_err());
    }

    // ---------- Cnt / Dec terminal flags ----------

    #[tokio::test]
    async fn cnt_marks_chain_contested_when_governance_satisfied() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let cnt = IdentityEvent::cnt(&v0).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier
            .verify_page(&[v0.clone(), cnt.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.is_contested());
        assert!(!v.is_decommissioned());
    }

    #[tokio::test]
    async fn dec_marks_chain_decommissioned_when_governance_satisfied() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let dec = IdentityEvent::dec(&v0).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier
            .verify_page(&[v0.clone(), dec.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.is_decommissioned());
        assert!(!v.is_contested());
    }

    /// #171 terminal-state gate: a non-terminal `Evl` extending a `Cnt`
    /// tip is structurally invalid. Tampered chain shape that the
    /// verifier rejects on read so consumers can't be tricked into
    /// honoring post-terminal extensions.
    #[tokio::test]
    async fn evl_extending_cnt_tip_rejected_as_post_terminal() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let cnt = IdentityEvent::cnt(&v0).unwrap();
        let post = IdentityEvent::evl(&cnt, None, None).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier.verify_page(&[v0, cnt, post]).await.unwrap();
        let err = verifier
            .finish()
            .await
            .expect_err("post-terminal extension must reject");
        assert!(
            err.to_string().contains("cannot extend terminal"),
            "expected Cnt-tombstone rejection, got {err}"
        );
    }

    /// #171 terminal-state gate: same shape for `Dec` — a non-terminal
    /// `Evl` extending a `Dec` tip is structurally invalid.
    #[tokio::test]
    async fn evl_extending_dec_tip_rejected_as_post_terminal() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let dec = IdentityEvent::dec(&v0).unwrap();
        let post = IdentityEvent::evl(&dec, None, None).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier.verify_page(&[v0, dec, post]).await.unwrap();
        let err = verifier
            .finish()
            .await
            .expect_err("post-terminal extension must reject");
        assert!(err.to_string().contains("cannot extend terminal"));
    }

    /// #171 terminal-state gate: `Cnt` extending a `Dec` tip is rejected
    /// uniformly with all other terminal-extensions. The legitimate
    /// Cnt-supersedes-Dec shape forks from a pre-Dec ancestor (creating
    /// divergence) — that requires non-tip parent-lookup and is deferred
    /// to #174. Until then `[..., Dec@N, Cnt@N+1]` (linear-and-contested)
    /// is structurally invalid; pin the rejection so the deferral surface
    /// is held by tests.
    #[tokio::test]
    async fn cnt_extending_dec_tip_rejected_as_post_terminal() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let dec = IdentityEvent::dec(&v0).unwrap();
        let cnt = IdentityEvent::cnt(&dec).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier.verify_page(&[v0, dec, cnt]).await.unwrap();
        let err = verifier
            .finish()
            .await
            .expect_err("Cnt extending Dec tip must reject (Cnt-supersedes-Dec deferred to #174)");
        assert!(err.to_string().contains("cannot extend terminal"));
    }

    #[tokio::test]
    async fn governance_failed_cnt_marks_terminal_but_unsatisfied() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let cnt = IdentityEvent::cnt(&v0).unwrap();

        // Anchor rejects every (said, policy). Icp soft-fails
        // (policy_satisfied=false); Cnt's governance check soft-fails. Per
        // design (`docs/design/iel/event-log.md` §"Chain States"), the
        // terminal flag is content-based: a chain with any Cnt event is
        // contested regardless of authorization. Auth status is in
        // policy_satisfied.
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AnchorRejectChecker);
        let mut verifier = IelVerifier::new(Some(&v0.prefix), checker);
        verifier
            .verify_page(&[v0.clone(), cnt.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.is_contested(), "Cnt content alone marks chain contested");
        assert!(!v.is_decommissioned());
        assert!(
            !v.policy_satisfied(),
            "governance soft-fail surfaces via policy_satisfied"
        );
    }

    #[tokio::test]
    async fn governance_failed_dec_marks_terminal_but_unsatisfied() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let dec = IdentityEvent::dec(&v0).unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AnchorRejectChecker);
        let mut verifier = IelVerifier::new(Some(&v0.prefix), checker);
        verifier
            .verify_page(&[v0.clone(), dec.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(
            v.is_decommissioned(),
            "Dec content alone marks chain decommissioned"
        );
        assert!(!v.is_contested());
        assert!(
            !v.policy_satisfied(),
            "governance soft-fail surfaces via policy_satisfied"
        );
    }

    // ---------- Cnt / Dec must preserve policies ----------

    #[tokio::test]
    async fn cnt_with_changed_auth_policy_rejected() {
        let auth1 = test_digest(b"auth-1");
        let auth2 = test_digest(b"auth-2");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth1, gov, TEST_TOPIC).unwrap();
        let mut cnt = IdentityEvent::cnt(&v0).unwrap();
        // Tamper: change auth_policy. The verifier must reject.
        cnt.auth_policy = auth2;
        cnt.derive_said().unwrap();

        let verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        let err = run(verifier, &[v0, cnt])
            .await
            .expect_err("expected verification failure");
        assert!(
            err.to_string().contains("must preserve auth_policy"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn dec_with_changed_governance_policy_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov1 = test_digest(b"gov-1");
        let gov2 = test_digest(b"gov-2");
        let v0 = IdentityEvent::icp(auth, gov1, TEST_TOPIC).unwrap();
        let mut dec = IdentityEvent::dec(&v0).unwrap();
        dec.governance_policy = gov2;
        dec.derive_said().unwrap();

        let verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        let err = run(verifier, &[v0, dec])
            .await
            .expect_err("expected verification failure");
        assert!(
            err.to_string().contains("must preserve governance_policy"),
            "unexpected error: {}",
            err
        );
    }

    // ---------- Four-cell immunity coverage ----------

    #[tokio::test]
    async fn icp_with_non_immune_auth_policy_rejected() {
        let auth = test_digest(b"non-immune-auth");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();

        // Only `gov` is immune; `auth` is not.
        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(ImmuneOnlyForChecker { immune: gov });
        let verifier = IelVerifier::new(Some(&v0.prefix), checker);
        let err = run(verifier, &[v0])
            .await
            .expect_err("expected verification failure");
        assert!(
            err.to_string().contains("non-immune auth_policy"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn icp_with_non_immune_governance_policy_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"non-immune-gov");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();

        // Only `auth` is immune; `gov` is not.
        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(ImmuneOnlyForChecker { immune: auth });
        let verifier = IelVerifier::new(Some(&v0.prefix), checker);
        let err = run(verifier, &[v0])
            .await
            .expect_err("expected verification failure");
        assert!(
            err.to_string().contains("non-immune governance_policy"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn evl_evolving_auth_policy_to_non_immune_rejected() {
        let auth1 = test_digest(b"auth-1");
        let auth2_non_immune = test_digest(b"auth-2-non-immune");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth1, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, Some(auth2_non_immune), None).unwrap();

        // auth1 and gov are immune; auth2 is not.
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(ImmuneSetChecker {
            immune: vec![auth1, gov],
        });
        let verifier = IelVerifier::new(Some(&v0.prefix), checker);
        let err = run(verifier, &[v0, v1])
            .await
            .expect_err("expected verification failure");
        assert!(
            err.to_string().contains("non-immune"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn evl_evolving_governance_policy_to_non_immune_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov1 = test_digest(b"gov-1");
        let gov2_non_immune = test_digest(b"gov-2-non-immune");
        let v0 = IdentityEvent::icp(auth, gov1, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, Some(gov2_non_immune)).unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(ImmuneSetChecker {
            immune: vec![auth, gov1],
        });
        let verifier = IelVerifier::new(Some(&v0.prefix), checker);
        let err = run(verifier, &[v0, v1])
            .await
            .expect_err("expected verification failure");
        assert!(
            err.to_string().contains("non-immune"),
            "unexpected error: {}",
            err
        );
    }

    // ---------- Divergence ----------

    #[tokio::test]
    async fn divergent_evls_produce_two_branches() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();

        let auth_a = test_digest(b"auth-a");
        let auth_b = test_digest(b"auth-b");
        let v1_a = IdentityEvent::evl(&v0, Some(auth_a), None).unwrap();
        let v1_b = IdentityEvent::evl(&v0, Some(auth_b), None).unwrap();

        // Order events by sort_priority (Evl == 1 for both) then SAID asc.
        let (first, second) = if v1_a.said.as_ref() < v1_b.said.as_ref() {
            (v1_a.clone(), v1_b.clone())
        } else {
            (v1_b.clone(), v1_a.clone())
        };

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier.verify_page(&[v0, first, second]).await.unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.is_divergent());
        assert_eq!(v.diverged_at_version(), Some(1));
        assert_eq!(v.branches().len(), 2);
        assert_eq!(v.current_event(), None); // divergent → no winner
    }

    #[tokio::test]
    async fn v0_divergence_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0_a = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        // Two distinct v0 events at the same version 0 — the divergence-at-v0
        // case the verifier must reject outright.
        let auth_b = test_digest(b"auth-b");
        let v0_b = IdentityEvent::icp(auth_b, gov, TEST_TOPIC).unwrap();

        let verifier = IelVerifier::new(None, always_pass());
        let err = run(verifier, &[v0_a, v0_b])
            .await
            .expect_err("expected v0 divergence to be rejected");
        assert!(
            err.to_string().contains("v0 divergence is not permitted"),
            "unexpected error: {}",
            err
        );
    }

    // ---------- Resume ----------

    #[tokio::test]
    async fn resume_extends_chain_after_save() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
        let token = verifier.finish().await.unwrap();

        // Resume and extend with another Evl.
        let v2 = IdentityEvent::evl(&v1, None, None).unwrap();
        let mut resumed = IelVerifier::resume(&token, always_pass()).unwrap();
        resumed
            .verify_page(std::slice::from_ref(&v2))
            .await
            .unwrap();
        let extended = resumed.finish().await.unwrap();

        assert_eq!(extended.last_governance_version(), Some(2));
        assert_eq!(extended.current_event().map(|e| e.said), Some(v2.said));
        assert_eq!(extended.auth_policy_at(&v0.said), Some(auth));
    }

    // ---------- Prefix / SAID mismatches ----------

    #[tokio::test]
    async fn prefix_mismatch_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();

        let bogus_prefix = test_digest(b"bogus-prefix");
        let mut verifier = IelVerifier::new(Some(&bogus_prefix), always_pass());
        assert!(verifier.verify_page(&[v0]).await.is_err());
    }

    #[tokio::test]
    async fn tampered_said_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let mut v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        v0.topic = "kels/iel/v1/identity/tampered".into();
        // Don't re-derive the SAID — the tamper is what we want to detect.

        let mut verifier = IelVerifier::new(None, always_pass());
        assert!(verifier.verify_page(&[v0]).await.is_err());
    }

    // ---------- Soft anchor fail at Icp ----------

    #[tokio::test]
    async fn icp_anchor_failure_is_soft() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();

        // is_anchored returns false everywhere; is_immune returns true.
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AnchorRejectChecker);
        let mut verifier = IelVerifier::new(Some(&v0.prefix), checker);
        verifier.verify_page(&[v0]).await.unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(!v.policy_satisfied());
        // Branch state still seeded (Icp's seeding is unconditional on the
        // anchor check, just as in SEL).
        assert_eq!(v.branches().len(), 1);
    }

    // ---------- Caller-bounded SAID querying + post-divergence soft-fail ----------

    #[tokio::test]
    async fn satisfied_saids_populates_for_pre_divergence_anchored_event() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier.check_satisfied([v0.said, v1.said]);
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        // Both events queried; both pre-divergence (chain non-divergent);
        // both auth-passed. Both in satisfied_saids.
        assert!(v.is_said_satisfied(&v0.said));
        assert!(v.is_said_satisfied(&v1.said));
        assert_eq!(v.satisfied_saids().len(), 2);
    }

    #[tokio::test]
    async fn satisfied_saids_excludes_unqueried_event() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();

        // Only v1 registered; v0 isn't.
        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier.check_satisfied([v1.said]);
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(!v.is_said_satisfied(&v0.said));
        assert!(v.is_said_satisfied(&v1.said));
    }

    #[tokio::test]
    async fn cnt_creates_divergence_at_its_version_so_cnt_not_in_satisfied_saids() {
        // Cnt creates divergence by extending an existing tip that isn't
        // the chain's max version. To reproduce in a fake-source setup,
        // build a chain where Evl@1 lands first, then a Cnt@1 extending v0
        // appears at the same version. The verifier observes divergence
        // at v=1, and per the design Cnt's own SAID is structurally NOT in
        // satisfied_saids regardless of the auth check.
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let evl = IdentityEvent::evl(&v0, None, None).unwrap();
        let cnt = IdentityEvent::cnt(&v0).unwrap();

        // Sort canonical: kind sort_priority places Evl=1 before Cnt=2.
        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier.check_satisfied([v0.said, evl.said, cnt.said]);
        verifier
            .verify_page(&[v0, evl.clone(), cnt.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert_eq!(v.diverged_at_version(), Some(1));
        // Pre-divergence v=0 — satisfied. v=1 events — NOT satisfied.
        assert!(!v.is_said_satisfied(&evl.said));
        assert!(!v.is_said_satisfied(&cnt.said));
        // Chain is contested (content-based) but no satisfied SAID at the
        // divergence version.
        assert!(v.is_contested());
    }

    #[tokio::test]
    async fn dec_lands_in_satisfied_saids_on_clean_chain() {
        // Dec only lands on a non-divergent chain (per routing). diverged_at
        // remains None, so Dec at v=1 is pre-divergence by predicate
        // (chain-non-divergent branch of `version < first_divergent_version
        // OR chain non-divergent`). With auth-pass, Dec lands satisfied.
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let dec = IdentityEvent::dec(&v0).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier.check_satisfied([dec.said]);
        verifier
            .verify_page(&[v0.clone(), dec.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert_eq!(v.diverged_at_version(), None);
        assert!(v.is_decommissioned());
        assert!(v.is_said_satisfied(&dec.said));
    }

    #[tokio::test]
    async fn structural_failure_post_divergence_still_returns_err() {
        // Even with the post-divergence soft-fail, structural rules stay HARD.
        // A Cnt with a tampered governance_policy must still bounce.
        let auth = test_digest(b"auth-policy");
        let gov1 = test_digest(b"gov-1");
        let gov2 = test_digest(b"gov-2");
        let v0 = IdentityEvent::icp(auth, gov1, TEST_TOPIC).unwrap();
        let evl_a = IdentityEvent::evl(&v0, None, None).unwrap();
        let mut cnt_b = IdentityEvent::cnt(&v0).unwrap();
        // Tamper structurally: Cnt must preserve governance_policy.
        cnt_b.governance_policy = gov2;
        cnt_b.derive_said().unwrap();

        let verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        // Verifier sees Evl-then-Cnt at v=1; Cnt's preservation check
        // structurally fails — HARD error regardless of post-divergence
        // status.
        let err = run(verifier, &[v0, evl_a, cnt_b])
            .await
            .expect_err("structural Cnt-policy-preservation must HARD-fail");
        assert!(
            err.to_string().contains("must preserve governance_policy"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn resume_rehydrates_queried_and_satisfied_saids() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();

        let mut verifier = IelVerifier::new(Some(&v0.prefix), always_pass());
        verifier.check_satisfied([v0.said, v1.said]);
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
        let token = verifier.finish().await.unwrap();
        assert!(token.is_said_satisfied(&v0.said));
        assert!(token.is_said_satisfied(&v1.said));

        // Resume: queried_saids and satisfied_saids carry across the
        // resume boundary (IEL/SE divergence from KEL's reset-on-resume).
        let v2 = IdentityEvent::evl(&v1, None, None).unwrap();
        let mut resumed = IelVerifier::resume(&token, always_pass()).unwrap();
        resumed
            .verify_page(std::slice::from_ref(&v2))
            .await
            .unwrap();
        let extended = resumed.finish().await.unwrap();

        assert!(extended.is_said_satisfied(&v0.said));
        assert!(extended.is_said_satisfied(&v1.said));
    }
}
