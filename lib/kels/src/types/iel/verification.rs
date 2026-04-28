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
//! - Cnt/Dec governance check is **soft** for the terminal-flag advance — a
//!   governance-failed Cnt/Dec sets `policy_satisfied=false` and does NOT
//!   mark the chain `is_contested` / `is_decommissioned`. The structural
//!   "must preserve policies" check is still hard.
//! - Immunity violations at Icp or Evl evolution are **hard**.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use verifiable_storage::{Chained, SelfAddressed};

use super::event::{IdentityEvent, IdentityEventKind};
use crate::{KelsError, types::PolicyChecker};

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
/// SE-side verification (round 12) will use to resolve `identity_event`
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
}

impl IelVerification {
    pub(crate) fn new(
        branches: Vec<IdentityBranchTip>,
        policy_history: BTreeMap<cesr::Digest256, (cesr::Digest256, cesr::Digest256)>,
        policy_satisfied: bool,
        diverged_at_version: Option<u64>,
        is_contested: bool,
        is_decommissioned: bool,
        last_governance_version: Option<u64>,
    ) -> Self {
        Self {
            branches,
            policy_history,
            policy_satisfied,
            diverged_at_version,
            is_contested,
            is_decommissioned,
            last_governance_version,
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

    /// True when an authorized `Cnt` event has landed on the chain.
    pub fn is_contested(&self) -> bool {
        self.is_contested
    }

    /// True when an authorized `Dec` event has landed on the chain.
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
    pub fn auth_policy_at(&self, said: &cesr::Digest256) -> Option<cesr::Digest256> {
        self.policy_history.get(said).map(|(a, _)| *a)
    }

    /// Same as [`auth_policy_at`], for `governance_policy`.
    pub fn governance_policy_at(&self, said: &cesr::Digest256) -> Option<cesr::Digest256> {
        self.policy_history.get(said).map(|(_, g)| *g)
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
    checker: Arc<dyn PolicyChecker + Send + Sync>,
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
            checker,
        }
    }

    /// Re-hydrate a verifier from a prior verification token. Subsequent
    /// `verify_page` calls extend the same per-branch state.
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
            checker,
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
            if !self.checker.is_immune(&event.auth_policy).await? {
                return Err(KelsError::VerificationFailed(format!(
                    "IEL Icp {} declares non-immune auth_policy {}",
                    event.said, event.auth_policy
                )));
            }
            if !self.checker.is_immune(&event.governance_policy).await? {
                return Err(KelsError::VerificationFailed(format!(
                    "IEL Icp {} declares non-immune governance_policy {}",
                    event.said, event.governance_policy
                )));
            }

            // Soft anchor check — Icp self-authorization. Failure leaves the
            // chain in `policy_satisfied=false` but does not abort.
            if !self
                .checker
                .is_anchored(&event.said, &event.auth_policy)
                .await?
            {
                self.policy_satisfied = false;
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

            let branch = self.branches.get(previous).ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "IEL event {} previous {} does not match any branch tip",
                    event.said, previous
                ))
            })?;

            let expected_version = branch.tip.version + 1;
            if event.version != expected_version {
                return Err(KelsError::VerificationFailed(format!(
                    "IEL event {} has version {} but expected {} (branch tip + 1)",
                    event.said, event.version, expected_version
                )));
            }

            // Anchor check against the branch's tracked governance_policy.
            // For Evl this is hard-fail (per SEL parity for governance kinds).
            // For Cnt/Dec we record the result and gate the terminal-flag
            // advance on it (soft-fail on the flag; the event is still in the
            // chain because the merge handler accepted it).
            let governance_satisfied = self
                .checker
                .is_anchored(&event.said, &branch.tracked_governance_policy)
                .await?;

            match event.kind {
                IdentityEventKind::Icp => {
                    return Err(KelsError::VerificationFailed(format!(
                        "IEL Icp event {} at version {} — Icp must be at v0",
                        event.said, event.version
                    )));
                }
                IdentityEventKind::Evl => {
                    if !governance_satisfied {
                        return Err(KelsError::VerificationFailed(format!(
                            "IEL Evl {} not anchored under tracked governance_policy {}",
                            event.said, branch.tracked_governance_policy
                        )));
                    }

                    // Per-kind discipline: Evl may evolve policies. Check
                    // immunity on any new value before adopting it.
                    let auth_changed = event.auth_policy != branch.tracked_auth_policy;
                    let gov_changed = event.governance_policy != branch.tracked_governance_policy;

                    if auth_changed && !self.checker.is_immune(&event.auth_policy).await? {
                        return Err(KelsError::VerificationFailed(format!(
                            "IEL Evl {} evolves auth_policy to non-immune {}",
                            event.said, event.auth_policy
                        )));
                    }
                    if gov_changed && !self.checker.is_immune(&event.governance_policy).await? {
                        return Err(KelsError::VerificationFailed(format!(
                            "IEL Evl {} evolves governance_policy to non-immune {}",
                            event.said, event.governance_policy
                        )));
                    }

                    new_branches.insert(
                        event.said,
                        IdentityBranchTip {
                            tip: event.clone(),
                            tracked_auth_policy: event.auth_policy,
                            tracked_governance_policy: event.governance_policy,
                            last_governance_version: Some(event.version),
                        },
                    );
                    self.policy_history
                        .insert(event.said, (event.auth_policy, event.governance_policy));
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

                    // Soft governance check for terminal-flag advance.
                    if !governance_satisfied {
                        self.policy_satisfied = false;
                    } else if event.kind.is_contest() {
                        self.is_contested = true;
                    } else {
                        self.is_decommissioned = true;
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

    /// Finish verification and produce the proof token.
    pub async fn finish(mut self) -> Result<IelVerification, KelsError> {
        self.flush_generation().await?;

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

        Ok(IelVerification::new(
            branches,
            self.policy_history,
            self.policy_satisfied,
            self.diverged_at_version,
            self.is_contested,
            self.is_decommissioned,
            last_governance_version,
        ))
    }
}

// ==================== Tests ====================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    const TEST_TOPIC: &str = "kels/iel/v1/identity/test";

    /// Test fake: every (said, policy) anchor passes; every policy is immune.
    struct AlwaysPassChecker;

    #[async_trait::async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn is_anchored(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<bool, KelsError> {
            Ok(true)
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
        async fn is_anchored(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<bool, KelsError> {
            Ok(false)
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
        async fn is_anchored(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<bool, KelsError> {
            Ok(true)
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
        async fn is_anchored(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<bool, KelsError> {
            Ok(true)
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

    #[tokio::test]
    async fn governance_failed_cnt_does_not_mark_terminal() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let cnt = IdentityEvent::cnt(&v0).unwrap();

        // Anchor rejects every (said, policy). Icp soft-fails (policy_satisfied=false);
        // Cnt's governance check soft-fails — the chain must NOT be marked
        // contested.
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AnchorRejectChecker);
        let mut verifier = IelVerifier::new(Some(&v0.prefix), checker);
        verifier
            .verify_page(&[v0.clone(), cnt.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(!v.is_contested());
        assert!(!v.is_decommissioned());
        assert!(!v.policy_satisfied());
    }

    #[tokio::test]
    async fn governance_failed_dec_does_not_mark_terminal() {
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

        assert!(!v.is_decommissioned());
        assert!(!v.policy_satisfied());
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
}
