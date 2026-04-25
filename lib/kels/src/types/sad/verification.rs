//! SAD Event Log verification (structural + policy authorization)

use std::{collections::HashMap, sync::Arc};

use verifiable_storage::{Chained, SelfAddressed};

use super::event::{SadEvent, SadEventKind};
use crate::KelsError;

// ==================== Policy Checker Trait ====================

/// Trait for checking policy satisfaction during chain verification.
///
/// `SelVerifier` calls this at each generation:
/// - v0: `self_satisfies(event)` — the inception must be authorized by its own write_policy
/// - v1+: `satisfies(event, &branch.tracked_write_policy)` — each advance must be authorized
///   by the branch's currently-tracked write_policy (seeded by v0, updated when Evl carries
///   a new write_policy *and* the evolution was authorized). Called unconditionally,
///   whether or not the policy changed. The returned value also gates whether the verifier
///   advances branch-state (tracked write_policy, tracked governance_policy, establishment
///   version, last governance version); a returned `false` freezes all policy-related state
///   on the branch for this event.
///
/// Implementations live outside `lib/kels` to avoid circular deps (e.g., `lib/policy`
/// calls `evaluate_anchored_policy` to check KEL anchoring).
#[async_trait::async_trait]
pub trait PolicyChecker: Send + Sync {
    /// Check if the advance to `new_event` is authorized by `previous_policy`.
    ///
    /// Evaluates `previous_policy` via anchoring — the endorsers required by
    /// `previous_policy` must have anchored `new_event.said` in their KELs.
    async fn satisfies(
        &self,
        new_event: &SadEvent,
        previous_policy: &cesr::Digest256,
    ) -> Result<bool, KelsError>;

    /// Check if v0 inception with this event is authorized.
    ///
    /// Evaluates `event.write_policy` via anchoring — endorsers must have
    /// anchored `event.said` in their KELs.
    async fn self_satisfies(&self, event: &SadEvent) -> Result<bool, KelsError>;
}

// ==================== Incremental Chain Verification ====================

/// Per-branch state for divergent SAD Event Logs.
#[derive(Debug, Clone)]
struct SadBranchState {
    tip: SadEvent,
    /// The effective write_policy for this branch.
    /// Seeded from v0 (Icp always has write_policy) and updated when an Evl
    /// event carries a new write_policy *and* the evolution was authorized
    /// by the previous policy. Used to authorize v1+ advances.
    tracked_write_policy: cesr::Digest256,
    /// The governance policy SAID tracked on this branch.
    /// `None` until the first governance_policy is declared.
    governance_policy: Option<cesr::Digest256>,
    /// Number of events since the last evaluation (or since chain start).
    events_since_evaluation: usize,
    /// Version of the most recent governance evaluation (Evl or Rpr) on this
    /// branch that passed both the governance check and the soft write_policy
    /// check. `None` until the first authorized evaluation. Monotonically
    /// advances (max) within a branch.
    last_governance_version: Option<u64>,
}

/// Streaming structural + policy verifier for SAD Event Logs.
///
/// Mirrors `KelVerifier` — verifies incrementally page by page without holding
/// the full chain in memory. Tracks per-branch state so that both forks of a
/// divergent chain are fully verified (SAID, prefix, topic, chain linkage,
/// and write_policy authorization via `PolicyChecker`).
///
/// The verifier never errors on policy failure — it records the result in
/// `policy_satisfied`. Structural errors (bad SAID, wrong prefix, etc.)
/// still return errors. Callers check `policy_satisfied()` on the verification
/// token to decide what to do (e.g., server returns 403, client logs a warning).
pub struct SelVerifier {
    /// Expected chain prefix. `None` on a fresh builder with no hydration and
    /// no caller-supplied prefix — latches to `event.prefix` at inception. Once
    /// set (latched or supplied), `verify_event` enforces that every event
    /// matches; a mismatch surfaces as `KelsError::VerificationFailed`.
    prefix: Option<cesr::Digest256>,
    topic: Option<String>,
    /// Branches keyed by tip SAID. Pre-divergence: one branch.
    branches: HashMap<cesr::Digest256, SadBranchState>,
    /// Events buffered for the current generation (same version).
    generation_buffer: Vec<SadEvent>,
    /// The version of the current buffered generation.
    current_generation_version: Option<u64>,
    saw_any_events: bool,
    policy_satisfied: bool,
    /// The version at which governance_policy was first established (v0 or v1).
    /// Chain-wide, set once.
    establishment_version: Option<u64>,
    /// The lowest version at which a second branch first appeared on the chain.
    /// Set once at first divergence, carried through to `SelVerification`.
    diverged_at_version: Option<u64>,
    /// Owned policy checker. Held as `Arc` so the verifier can outlive any
    /// individual call site and so `SadEventBuilder` can stash one and reuse
    /// it across `new`/`resume` paths without lifetime gymnastics.
    checker: Arc<dyn PolicyChecker + Send + Sync>,
}

impl SelVerifier {
    pub fn new(
        prefix: Option<&cesr::Digest256>,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
    ) -> Self {
        Self {
            prefix: prefix.copied(),
            topic: None,
            branches: HashMap::new(),
            generation_buffer: Vec::new(),
            current_generation_version: None,
            saw_any_events: false,
            policy_satisfied: true,
            establishment_version: None,
            diverged_at_version: None,
            checker,
        }
    }

    pub fn is_divergent(&self) -> bool {
        self.branches.len() > 1
    }

    /// Verify a single event's SAID, prefix, and topic.
    fn verify_event(&self, event: &SadEvent) -> Result<(), KelsError> {
        event.verify_said()?;

        if let Some(ref expected) = self.prefix
            && event.prefix != *expected
        {
            return Err(KelsError::VerificationFailed(format!(
                "SAD event {} prefix {} doesn't match SEL prefix {}",
                event.said, event.prefix, expected
            )));
        }

        if let Some(ref expected) = self.topic
            && event.topic != *expected
        {
            return Err(KelsError::VerificationFailed(format!(
                "SAD event {} topic {} doesn't match SEL topic {}",
                event.said, event.topic, expected
            )));
        }

        Ok(())
    }

    /// Process a complete generation (all events at the same version).
    async fn flush_generation(&mut self) -> Result<(), KelsError> {
        let events = std::mem::take(&mut self.generation_buffer);
        let version = match self.current_generation_version.take() {
            Some(v) => v,
            None => return Ok(()),
        };

        if events.is_empty() {
            return Ok(());
        }

        // Structural validation first — before any chain state reasoning
        for event in &events {
            event
                .validate_structure()
                .map_err(KelsError::VerificationFailed)?;
        }

        if self.branches.is_empty() {
            // First generation — inception (version 0)
            if events.len() != 1 {
                return Err(KelsError::VerificationFailed(
                    "Multiple events at version 0".into(),
                ));
            }

            let event = &events[0];
            event.verify_prefix()?;

            // Policy check: v0 must self-satisfy
            if !self.checker.self_satisfies(event).await? {
                self.policy_satisfied = false;
            }

            // Track governance_policy if declared on v0
            let governance_policy = event.governance_policy;
            if governance_policy.is_some() {
                self.establishment_version = Some(0);
            }

            // Seed tracked_write_policy from v0. validate_structure guarantees
            // Icp has Some(write_policy).
            #[allow(clippy::expect_used)]
            let tracked_write_policy = event
                .write_policy
                .expect("Icp event must have write_policy per validate_structure");

            self.branches.insert(
                event.said,
                SadBranchState {
                    tip: event.clone(),
                    tracked_write_policy,
                    governance_policy,
                    events_since_evaluation: 0,
                    last_governance_version: None,
                },
            );

            // Latch the chain prefix from v0 if the caller didn't supply one.
            // On subsequent events the `verify_event` check will enforce equality
            // against this value; a fresh-builder incept that derives a prefix
            // different from what the caller expected surfaces there.
            if self.prefix.is_none() {
                self.prefix = Some(event.prefix);
            }
            return Ok(());
        }

        // Max 2 events per generation (owner + adversary fork)
        if events.len() > 2 {
            return Err(KelsError::VerificationFailed(format!(
                "Generation at version {} has {} events, max 2 allowed",
                version,
                events.len()
            )));
        }

        // Detect divergence: more events than branches means a new fork. Mirrors
        // the KEL verifier's detection at types/kel/verification.rs. Set once —
        // later generations on a divergent chain don't overwrite the first
        // divergence version.
        if events.len() > self.branches.len() && self.diverged_at_version.is_none() {
            self.diverged_at_version = Some(version);
        }

        let mut new_branches: HashMap<cesr::Digest256, SadBranchState> = HashMap::new();

        for event in &events {
            let previous = event.previous.as_ref().ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "Non-inception SAD event {} has no previous event",
                    event.said,
                ))
            })?;

            let branch = self.branches.get(previous).ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "SAD event {} previous {} does not match any branch tip",
                    event.said, previous,
                ))
            })?;

            let expected_version = branch.tip.version + 1;
            if event.version != expected_version {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD event {} has version {} but expected {} (branch tip version + 1)",
                    event.said, event.version, expected_version
                )));
            }

            // Policy check: every v1+ event must satisfy the branch's tracked write_policy.
            // Defense-in-depth: when this check fails, we also refuse to advance
            // `tracked_write_policy` below, so subsequent events on the same branch
            // keep failing against the still-legitimate previous policy. This gives
            // consumers multiple soft signals instead of relying on a single
            // `policy_satisfied` flag being checked.
            let write_policy_satisfied = self
                .checker
                .satisfies(event, &branch.tracked_write_policy)
                .await?;
            if !write_policy_satisfied {
                self.policy_satisfied = false;
            }

            // Guard: all non-Icp/non-Est kinds require governance_policy established
            if !event.kind.is_inception()
                && event.kind != SadEventKind::Est
                && branch.governance_policy.is_none()
            {
                return Err(KelsError::VerificationFailed(format!(
                    "SAD event {} kind {} requires governance_policy to be established",
                    event.said, event.kind,
                )));
            }

            // Kind-specific chain-state logic
            let (
                governance_policy,
                events_since_evaluation,
                tracked_write_policy,
                last_governance_version,
            ) = match event.kind {
                SadEventKind::Icp => {
                    // Icp at v1+ is rejected by validate_structure (version != 0)
                    unreachable!("Icp at v1+ should be rejected by validate_structure")
                }
                SadEventKind::Est => {
                    // Est: governance_policy declaration — only valid when branch has none from v0
                    if branch.governance_policy.is_some() {
                        return Err(KelsError::VerificationFailed(format!(
                            "SAD event {} Est rejected — governance_policy already established from v0",
                            event.said,
                        )));
                    }
                    // Defense-in-depth: skip state advances on soft wp-fail. See R5/R6 audit.
                    // events_since_evaluation = 1 stays unconditional — an unauthorized Est
                    // still occupies a slot in the evaluation window (same as an unauthorized Upd).
                    // tracked_write_policy unchanged — Est forbids write_policy (validate_structure).
                    let (new_est_version, new_gp) = if write_policy_satisfied {
                        (Some(1), event.governance_policy)
                    } else {
                        (self.establishment_version, branch.governance_policy)
                    };
                    // Chain-wide assignment (not per-branch): the handler's repair-floor
                    // guard (services/sadstore/src/handlers.rs) relies on this being the
                    // earliest establishment point across all branches. In divergent
                    // scenarios this may not match the tie-break winner's branch state —
                    // see `SelVerification::establishment_version()` docstring.
                    self.establishment_version = new_est_version;
                    (
                        new_gp,
                        1,
                        branch.tracked_write_policy,
                        branch.last_governance_version,
                    )
                }
                kind if kind.evaluates_governance() => {
                    // Evl or Rpr: evaluate against tracked governance_policy
                    let tracked = branch.governance_policy.as_ref().ok_or_else(|| {
                        KelsError::VerificationFailed(format!(
                            "SAD event {} {} but no governance_policy established",
                            event.said, event.kind,
                        ))
                    })?;

                    if !self.checker.satisfies(event, tracked).await? {
                        return Err(KelsError::VerificationFailed(format!(
                            "SAD event {} governance policy not satisfied",
                            event.said,
                        )));
                    }

                    // Defense-in-depth: when the soft write_policy check above failed,
                    // skip all branch-state advances driven by this event — even those
                    // authorized by the governance check that just passed. A consumer
                    // that bypasses policy_satisfied() then sees unchanged seal/policy
                    // state for an unauthorized event. (See R5/R6 audit for rationale.)
                    let new_last_gov_version = if write_policy_satisfied {
                        Some(match branch.last_governance_version {
                            Some(existing) => existing.max(event.version),
                            None => event.version,
                        })
                    } else {
                        branch.last_governance_version
                    };

                    // Evl allows governance_policy evolution; Rpr forbids it (validate_structure).
                    let new_gp = if write_policy_satisfied {
                        event.governance_policy.or(Some(*tracked))
                    } else {
                        Some(*tracked)
                    };
                    // Evl with Some(write_policy) = policy evolution. None = pure evaluation.
                    // Rpr forbids write_policy entirely (validate_structure).
                    let new_wp = if write_policy_satisfied {
                        event.write_policy.unwrap_or(branch.tracked_write_policy)
                    } else {
                        branch.tracked_write_policy
                    };
                    (new_gp, 0, new_wp, new_last_gov_version)
                }
                SadEventKind::Upd => {
                    // Normal event — increment counter, check bound
                    let count = branch.events_since_evaluation + 1;
                    if count > crate::MAX_NON_EVALUATION_EVENTS {
                        return Err(KelsError::VerificationFailed(format!(
                            "SAD event {} exceeds evaluation bound ({} non-evaluation events, max {})",
                            event.said,
                            count,
                            crate::MAX_NON_EVALUATION_EVENTS,
                        )));
                    }
                    // tracked_write_policy unchanged — Upd forbids write_policy (validate_structure)
                    (
                        branch.governance_policy,
                        count,
                        branch.tracked_write_policy,
                        branch.last_governance_version,
                    )
                }
                _ => unreachable!("All SadEventKind variants handled"),
            };

            new_branches.insert(
                event.said,
                SadBranchState {
                    tip: event.clone(),
                    tracked_write_policy,
                    governance_policy,
                    events_since_evaluation,
                    last_governance_version,
                },
            );
        }

        // Keep un-extended branches
        for (said, state) in &self.branches {
            if !events.iter().any(|e| e.previous.as_ref() == Some(said)) {
                new_branches.insert(*said, state.clone());
            }
        }

        self.branches = new_branches;
        Ok(())
    }

    /// Verify a page of events incrementally.
    pub async fn verify_page(&mut self, events: &[SadEvent]) -> Result<(), KelsError> {
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

    pub async fn finish(mut self) -> Result<super::event::SelVerification, KelsError> {
        self.flush_generation().await?;

        if !self.saw_any_events {
            return Err(KelsError::VerificationFailed("Empty SAD Event Log".into()));
        }

        if self.branches.is_empty() {
            return Err(KelsError::VerificationFailed(
                "No tip after verification".into(),
            ));
        }

        // Global invariant: at least one branch must have a governance policy established
        if !self
            .branches
            .values()
            .any(|b| b.governance_policy.is_some())
        {
            return Err(KelsError::VerificationFailed(
                "SAD Event Log has no governance_policy established — Icp or Est must declare one"
                    .into(),
            ));
        }

        // Chain-wide last_governance_version: min across tip branches' per-branch
        // values. In divergent chains this is the weakest seal — if any branch
        // has not advanced past version V, repair below V must still be allowed
        // on that branch. `None` on any branch collapses the chain-wide value to
        // `None` (no authorized evaluation on at least one branch).
        let last_governance_version = self
            .branches
            .values()
            .map(|b| b.last_governance_version)
            .reduce(|acc, v| match (acc, v) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None,
            })
            .flatten();

        // Deterministic tie-break: higher version wins; equal versions break
        // on lexicographically greater SAID. Matters for divergent chains so
        // `verification.write_policy()` is reproducible across callers.
        let winning_branch = self
            .branches
            .into_values()
            .max_by(|a, b| {
                a.tip
                    .version
                    .cmp(&b.tip.version)
                    .then_with(|| a.tip.said.as_ref().cmp(b.tip.said.as_ref()))
            })
            .ok_or_else(|| KelsError::VerificationFailed("No tip after verification".into()))?;

        Ok(super::event::SelVerification::new(
            winning_branch.tip,
            winning_branch.tracked_write_policy,
            winning_branch.governance_policy,
            winning_branch.events_since_evaluation,
            self.policy_satisfied,
            last_governance_version,
            self.establishment_version,
            self.diverged_at_version,
        ))
    }

    /// Resume a verifier from a prior verification token.
    ///
    /// Rehydrates single-branch state (`tip`, `tracked_write_policy`, `governance_policy`,
    /// `events_since_evaluation`, `last_governance_version`) plus chain-wide
    /// `establishment_version` and `policy_satisfied`, so subsequent `verify_page`
    /// calls continue from where the prior verification left off instead of
    /// re-verifying from inception.
    ///
    /// Parallel to `KelVerifier::resume`.
    ///
    /// **Precondition: non-divergent tokens only.** `SelVerification` carries a
    /// single tie-break winner, so a resumed verifier cannot reconstruct the
    /// losing branch. If `verification.diverged_at_version().is_some()`, resume
    /// returns `KelsError::CannotResumeDivergentChain` and the caller must
    /// re-verify the chain from inception.
    pub fn resume(
        verification: &super::event::SelVerification,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
    ) -> Result<Self, KelsError> {
        if verification.diverged_at_version().is_some() {
            return Err(KelsError::CannotResumeDivergentChain);
        }

        let tip = verification.current_event().clone();

        // The chain's prefix is authoritative from the verification tip — no
        // caller-supplied prefix. Subsequent `verify_page` calls get the same
        // strict prefix check as a latched fresh verifier would.
        let prefix = tip.prefix;

        let mut branches = HashMap::new();
        branches.insert(
            tip.said,
            SadBranchState {
                tip: tip.clone(),
                tracked_write_policy: *verification.write_policy(),
                governance_policy: verification.governance_policy().copied(),
                events_since_evaluation: verification.events_since_evaluation(),
                last_governance_version: verification.last_governance_version(),
            },
        );

        Ok(Self {
            prefix: Some(prefix),
            topic: Some(tip.topic.clone()),
            branches,
            generation_buffer: Vec::new(),
            current_generation_version: None,
            saw_any_events: true,
            policy_satisfied: verification.policy_satisfied(),
            establishment_version: verification.establishment_version(),
            diverged_at_version: None,
            checker,
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
// Happy-path fixtures delegate to `SadEventBuilder`. Fixtures below that
// construct events directly — `create_v0_no_evaluation`, the `add_governance_*`
// mutators, and the inline v0/v1 builds inside individual rejection tests —
// do so because those tests exercise the verifier's integrity against shapes
// the builder refuses by design (partial chains, wrong-version or wrong-kind
// events, divergent branches, bound violations). Routing them through the
// builder would defeat their purpose.
mod tests {
    use verifiable_storage::{Chained, SelfAddressed};

    use super::super::event::{SadEvent, SadEventKind};
    use super::*;
    use crate::sad_builder::SadEventBuilder;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    /// Create a v0 event with governance_policy declared.
    fn create_v0_with_evaluation(wp: cesr::Digest256) -> SadEvent {
        let gp = test_digest(b"evaluation-policy");
        let mut builder = SadEventBuilder::new(None, None, None);
        builder
            .incept("kels/sad/v1/keys/mlkem", wp, gp)
            .expect("incept produces a valid v0 with governance");
        builder
            .pending_events()
            .first()
            .expect("incept stages one event")
            .clone()
    }

    /// Create a v0 event without evaluation (prefix stays deterministic).
    fn create_v0_no_evaluation(wp: cesr::Digest256) -> SadEvent {
        SadEvent::icp("kels/sad/v1/keys/mlkem", wp, None).unwrap()
    }

    /// Declare governance_policy on an event (Est kind) and increment.
    fn add_governance_declaration(event: &mut SadEvent) {
        let gp = test_digest(b"evaluation-policy");
        event.kind = SadEventKind::Est;
        event.governance_policy = Some(gp);
        event.write_policy = None; // Est forbids write_policy
        event.increment().unwrap();
    }

    /// Set Evl kind and increment (evaluation, no policy evolution).
    fn add_governance_evaluation(event: &mut SadEvent) {
        event.kind = SadEventKind::Evl;
        event.write_policy = None; // pure evaluation
        event.increment().unwrap();
    }

    struct AlwaysPassChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn satisfies(&self, _: &SadEvent, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
        async fn self_satisfies(&self, _: &SadEvent) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    struct RejectingChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for RejectingChecker {
        async fn satisfies(&self, _: &SadEvent, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(false)
        }
        async fn self_satisfies(&self, _: &SadEvent) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    struct RejectInceptionChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for RejectInceptionChecker {
        async fn satisfies(&self, _: &SadEvent, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
        async fn self_satisfies(&self, _: &SadEvent) -> Result<bool, KelsError> {
            Ok(false)
        }
    }

    /// Test-only `PolicyChecker` that accepts governance_policy evaluations
    /// and rejects write_policy evaluations. Disambiguates the two by comparing
    /// the requested policy SAID against the stored `governance_policy`.
    ///
    /// **Callers must not reuse the same SAID for write_policy and
    /// governance_policy in the same test** — both checks would then accept,
    /// masking write_policy rejection. Tests using distinct `test_digest(b"...")`
    /// labels are already safe.
    struct AcceptEvaluationRejectWriteChecker {
        governance_policy: cesr::Digest256,
    }
    #[async_trait::async_trait]
    impl PolicyChecker for AcceptEvaluationRejectWriteChecker {
        async fn satisfies(
            &self,
            _: &SadEvent,
            policy: &cesr::Digest256,
        ) -> Result<bool, KelsError> {
            Ok(*policy == self.governance_policy)
        }
        async fn self_satisfies(&self, _: &SadEvent) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    // ==================== Original tests (updated with kinds) ====================

    #[tokio::test]
    async fn test_sel_verifier_valid_chain() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Upd;
        v1.write_policy = None;
        v1.governance_policy = None;
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        assert!(verifier.verify_page(&[v0.clone(), v1]).await.is_ok());
        assert!(!verifier.is_divergent());
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_event().version, 1);
    }

    #[tokio::test]
    async fn test_sel_verifier_empty_fails() {
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let verifier = SelVerifier::new(Some(&test_digest(b"test")), Arc::clone(&checker));
        assert!(verifier.finish().await.is_err());
    }

    #[tokio::test]
    async fn test_sel_verifier_wrong_version_fails() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Upd;
        v1.write_policy = None;
        v1.governance_policy = None;
        v1.increment().unwrap();
        v1.version = 5;
        v1.derive_said().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("has version 5 but expected 1"),
            "Expected version error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_sel_verifier_multi_page() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Upd;
        v1.write_policy = None;
        v1.governance_policy = None;
        v1.increment().unwrap();
        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        assert!(verifier.verify_page(&[v0]).await.is_ok());
        assert!(verifier.verify_page(&[v1, v2]).await.is_ok());

        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_event().version, 2);
    }

    #[tokio::test]
    async fn test_same_write_policy_authorized() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Upd;
        v1.write_policy = None;
        v1.governance_policy = None;
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(verification.policy_satisfied());
    }

    #[tokio::test]
    async fn test_evolving_write_policy_authorized() {
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let v0 = create_v0_with_evaluation(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Evl;
        v1.write_policy = Some(wp2);
        v1.governance_policy = None;
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(verification.policy_satisfied());
        // Tracked write_policy updated from Evl
        assert_eq!(verification.write_policy(), &wp2);
    }

    #[tokio::test]
    async fn test_rejected_write_policy_evolution() {
        // An Evl that evolves write_policy must be authorized against the
        // *previous* write_policy. Use AcceptEvaluationRejectWriteChecker so
        // the governance_policy evaluation passes (no hard error) but the
        // write_policy evaluation fails (soft rejection). This cleanly isolates
        // the write_policy rejection path.
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let gp = test_digest(b"evaluation-policy"); // matches create_v0_with_evaluation
        let v0 = create_v0_with_evaluation(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Evl;
        v1.write_policy = Some(wp2);
        v1.governance_policy = None;
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(AcceptEvaluationRejectWriteChecker {
                governance_policy: gp,
            });
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(
            !verification.policy_satisfied(),
            "Expected policy_satisfied=false — previous write_policy rejected the evolution"
        );
        // Defense-in-depth: tracked_write_policy did NOT advance to wp2 because
        // the soft write_policy check failed. Chain state remains authorized
        // against the legitimate previous policy.
        assert_eq!(verification.write_policy(), &wp1);
    }

    #[tokio::test]
    async fn test_evl_without_write_policy_inherits_tracked() {
        let wp1 = test_digest(b"write-policy-1");
        let v0 = create_v0_with_evaluation(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Evl;
        v1.write_policy = None;
        v1.governance_policy = None;
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        // Pure evaluation — tracked write_policy inherited from v0
        assert_eq!(verification.write_policy(), &wp1);
    }

    #[tokio::test]
    async fn test_evl_evolution_rejected_does_not_advance_tracked_policy() {
        // Defense-in-depth: when Evl evolves write_policy but the previous
        // policy rejects the advance, tracked_write_policy must remain at the
        // previous value. Any subsequent event on this branch will then be
        // checked against the legitimate previous policy, not the attacker's
        // proposed replacement. All three branch-state advances driven by the
        // event (tracked_write_policy, tracked governance_policy, and
        // last_governance_version) are gated on the same soft-pass flag.
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let gp = test_digest(b"evaluation-policy"); // matches create_v0_with_evaluation
        let v0 = create_v0_with_evaluation(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Evl;
        v1.write_policy = Some(wp2);
        v1.governance_policy = None;
        v1.increment().unwrap();

        // Accepts governance_policy evaluation, rejects write_policy authorization.
        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(AcceptEvaluationRejectWriteChecker {
                governance_policy: gp,
            });
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(
            !verification.policy_satisfied(),
            "Expected policy_satisfied=false because the previous write_policy rejected the evolution"
        );
        // tracked_write_policy did NOT advance — advance is gated on the soft check.
        assert_eq!(verification.write_policy(), &wp1);
        // last_governance_version did NOT advance either — same gate.
        assert_eq!(
            verification.last_governance_version(),
            None,
            "last_governance_version must not advance when the event soft-failed the write_policy check"
        );
    }

    #[tokio::test]
    async fn test_evl_rejected_wp_does_not_advance_governance_policy() {
        // Defense-in-depth: when an Evl soft-fails the write_policy check,
        // the branch's tracked governance_policy must stay at the previous
        // value. We verify this indirectly by submitting a v2 Evl whose hard
        // governance check only succeeds if tracked gp is still gp1 (not the
        // attacker's gp_attacker that v1 proposed). AcceptEvaluationRejectWriteChecker
        // only accepts checks against gp1, so if tracked gp had advanced to
        // gp_attacker, v2's hard governance check would fail and abort verification.
        let wp1 = test_digest(b"write-policy-1");
        let wp_attacker = test_digest(b"write-policy-attacker");
        let gp1 = test_digest(b"evaluation-policy"); // matches create_v0_with_evaluation
        let gp_attacker = test_digest(b"evaluation-policy-attacker");
        let v0 = create_v0_with_evaluation(wp1);

        // v1: attacker-crafted Evl evolving both wp and gp.
        // wp soft check (against tracked wp1): FAILS.
        // governance hard check (against tracked gp1): PASSES.
        // With the gate: tracked gp stays at gp1, last_governance_version stays None.
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Evl;
        v1.write_policy = Some(wp_attacker);
        v1.governance_policy = Some(gp_attacker);
        v1.increment().unwrap();

        // v2: a following Evl. wp stays attacker (inherited), gp unchanged.
        // If the v1 gp advance was gated (fix): tracked gp is gp1, v2's hard
        // governance check against gp1 passes → verification succeeds with
        // policy_satisfied=false.
        // If the v1 gp advance was NOT gated (pre-fix): tracked gp is gp_attacker,
        // v2's hard governance check against gp_attacker fails → HARD ERROR.
        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.kind = SadEventKind::Evl;
        v2.write_policy = None;
        v2.governance_policy = None;
        v2.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(AcceptEvaluationRejectWriteChecker {
                governance_policy: gp1,
            });
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let verification = verifier
            .finish()
            .await
            .expect("verification must succeed — tracked gp should still be gp1 on v2");
        assert!(
            !verification.policy_satisfied(),
            "wp soft-failed on v1 and v2, policy_satisfied must be false"
        );
        assert_eq!(verification.write_policy(), &wp1);
        // last_governance_version stays None: v1's wp soft-fail blocked the seal
        // advance, and v2's wp soft-fail blocks it again.
        assert_eq!(verification.last_governance_version(), None);
    }

    #[tokio::test]
    async fn test_est_rejected_wp_does_not_establish_governance_policy() {
        // Defense-in-depth: when an Est soft-fails the write_policy check,
        // establishment_version and branch.governance_policy must NOT advance.
        // Mirrors the R5/R6 gate on the Evl/Rpr arm for the Est arm.
        let wp1 = test_digest(b"write-policy-1");
        let gp_attacker = test_digest(b"evaluation-policy-attacker");
        let gp_legit = test_digest(b"evaluation-policy-legit");

        let v0 = create_v0_no_evaluation(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Est;
        v1.write_policy = None;
        v1.governance_policy = Some(gp_attacker);
        v1.increment().unwrap();

        // AcceptEvaluationRejectWriteChecker accepts only checks against gp_legit.
        // The wp check (against tracked wp1) returns false → soft-fail.
        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(AcceptEvaluationRejectWriteChecker {
                governance_policy: gp_legit,
            });
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap_err();
        // finish() rejects: the gate kept branch.governance_policy = None, so
        // "SAD Event Log has no governance_policy" fires. This proves Est's
        // governance_policy advance was blocked by the soft wp-fail.
        assert!(
            verification.to_string().contains("no governance_policy"),
            "Expected no-evaluation error because the soft-failed Est did not establish governance_policy, got: {}",
            verification
        );
    }

    #[tokio::test]
    async fn test_divergent_est_soft_fail_does_not_poison_other_branch() {
        // Divergent Est at v1: branch A carries gp_legit and soft-passes the wp
        // check; branch B carries gp_attacker and soft-fails. The R6 per-branch
        // gate keeps branch B's `governance_policy = None`, but `establishment_version`
        // is chain-wide and advances to Some(1) via branch A. This pins the
        // intentional chain-wide/per-branch asymmetry: consumers reading
        // `establishment_version()` without gating on `policy_satisfied()` may
        // see a value that doesn't match the tie-break winner's branch state.
        let wp1 = test_digest(b"write-policy-1");
        let gp_legit = test_digest(b"evaluation-policy-legit");
        let gp_attacker = test_digest(b"evaluation-policy-attacker");

        let v0 = create_v0_no_evaluation(wp1);

        let mut v1_a = v0.clone();
        v1_a.content = Some(test_digest(b"content_a"));
        v1_a.kind = SadEventKind::Est;
        v1_a.write_policy = None;
        v1_a.governance_policy = Some(gp_legit);
        v1_a.increment().unwrap();

        let mut v1_b = v0.clone();
        v1_b.content = Some(test_digest(b"content_b"));
        v1_b.kind = SadEventKind::Est;
        v1_b.write_policy = None;
        v1_b.governance_policy = Some(gp_attacker);
        v1_b.increment().unwrap();

        // Checker accepts the wp soft check only for events whose
        // governance_policy is gp_legit. Est doesn't trigger the governance hard
        // check, so this is the only checker call path exercised per event.
        struct AcceptLegitEstChecker {
            legit_gp: cesr::Digest256,
        }
        #[async_trait::async_trait]
        impl PolicyChecker for AcceptLegitEstChecker {
            async fn satisfies(
                &self,
                event: &SadEvent,
                _: &cesr::Digest256,
            ) -> Result<bool, KelsError> {
                Ok(event.governance_policy == Some(self.legit_gp))
            }
            async fn self_satisfies(&self, _: &SadEvent) -> Result<bool, KelsError> {
                Ok(true)
            }
        }

        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(AcceptLegitEstChecker { legit_gp: gp_legit });
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier
            .verify_page(&[v0.clone(), v1_a.clone(), v1_b.clone()])
            .await
            .unwrap();
        let verification = verifier.finish().await.unwrap();

        // Branch B soft-failed wp → chain-wide policy_satisfied is false.
        assert!(
            !verification.policy_satisfied(),
            "Branch B soft-failed wp; policy_satisfied must be false"
        );
        // Chain-wide: set by branch A's successful Est, not reset by B's soft-fail.
        assert_eq!(verification.establishment_version(), Some(1));
        // Est doesn't evaluate, regardless of which branch tie-break picks.
        assert_eq!(verification.last_governance_version(), None);
        // tracked_write_policy remains v0's wp (Est forbids wp evolution).
        assert_eq!(verification.write_policy(), &wp1);

        // Documenting the asymmetry: if tie-break selects branch B (whose per-branch
        // governance_policy stayed None because of the R6 gate), the token carries
        // establishment_version=Some(1) alongside a tip whose branch had no gp.
        // This is intentional; consumers that treat the accessor as branch-scoped
        // must gate on policy_satisfied() first.
        let winner_is_b = v1_b.said.as_ref() > v1_a.said.as_ref();
        assert_eq!(
            verification.current_event().said,
            if winner_is_b { v1_b.said } else { v1_a.said }
        );
    }

    #[tokio::test]
    async fn test_rpr_inherits_tracked_write_policy() {
        // Rpr cannot carry write_policy (validate_structure forbids it).
        // The verifier must leave tracked_write_policy unchanged across Rpr.
        let wp1 = test_digest(b"write-policy-1");
        let v0 = create_v0_with_evaluation(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Rpr;
        v1.write_policy = None;
        v1.governance_policy = None; // Rpr forbids governance_policy
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        // Rpr inherits wp1 from branch state
        assert_eq!(verification.write_policy(), &wp1);
    }

    #[tokio::test]
    async fn test_multi_step_write_policy_evolution() {
        // v0 Icp(wp1) → v1 Est → v2 Evl(wp2) → v3 Evl(wp3).
        // After verification, tracked_write_policy must equal wp3 — each Evl
        // advances from the previously-tracked policy, not from v0's seed.
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let wp3 = test_digest(b"write-policy-3");

        let v0 = create_v0_no_evaluation(wp1);
        let mut v1 = v0.clone();
        add_governance_declaration(&mut v1); // Est @ v1 establishes governance_policy

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.kind = SadEventKind::Evl;
        v2.write_policy = Some(wp2);
        v2.governance_policy = None;
        v2.increment().unwrap();

        let mut v3 = v2.clone();
        v3.content = Some(test_digest(b"content3"));
        v3.kind = SadEventKind::Evl;
        v3.write_policy = Some(wp3);
        v3.governance_policy = None;
        v3.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier
            .verify_page(&[v0.clone(), v1, v2, v3])
            .await
            .unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(verification.policy_satisfied());
        assert_eq!(verification.write_policy(), &wp3);
    }

    #[tokio::test]
    async fn test_multi_step_evolution_rejected_keeps_seed_policy() {
        // Chain: v0 Icp(wp1) → v1 Evl(wp2) → v2 Evl(wp3). The checker rejects
        // every write_policy check. Because advance is gated on the soft check,
        // neither v1 nor v2 advances tracked_write_policy, and the final
        // tracked value remains wp1. Combined with
        // test_multi_step_write_policy_evolution (which proves tracked advances
        // to wp3 under AlwaysPassChecker), the pair covers the advance-and-check
        // loop in both directions.
        let wp1 = test_digest(b"write-policy-1");
        let wp2 = test_digest(b"write-policy-2");
        let wp3 = test_digest(b"write-policy-3");
        let gp = test_digest(b"evaluation-policy"); // matches create_v0_with_evaluation

        let v0 = create_v0_with_evaluation(wp1);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Evl;
        v1.write_policy = Some(wp2);
        v1.governance_policy = None;
        v1.increment().unwrap();

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.kind = SadEventKind::Evl;
        v2.write_policy = Some(wp3);
        v2.governance_policy = None;
        v2.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(AcceptEvaluationRejectWriteChecker {
                governance_policy: gp,
            });
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(
            !verification.policy_satisfied(),
            "Both v1 and v2 evolutions must soft-fail under this checker"
        );
        // Advance is gated on soft-check — neither v1 nor v2 advanced tracked.
        assert_eq!(verification.write_policy(), &wp1);
    }

    #[tokio::test]
    async fn test_divergent_branches_tracked_write_policy_tiebreak_deterministic() {
        // Two divergent Evl branches at v1 carry different new write_policies.
        // finish() must pick one deterministically regardless of input order.
        let wp0 = test_digest(b"write-policy-0");
        let wp_a = test_digest(b"write-policy-a");
        let wp_b = test_digest(b"write-policy-b");
        let v0 = create_v0_with_evaluation(wp0);

        let mut v1_a = v0.clone();
        v1_a.content = Some(test_digest(b"content_a"));
        v1_a.kind = SadEventKind::Evl;
        v1_a.write_policy = Some(wp_a);
        v1_a.governance_policy = None;
        v1_a.increment().unwrap();

        let mut v1_b = v0.clone();
        v1_b.content = Some(test_digest(b"content_b"));
        v1_b.kind = SadEventKind::Evl;
        v1_b.write_policy = Some(wp_b);
        v1_b.governance_policy = None;
        v1_b.increment().unwrap();

        // Expected tie-break: higher version wins; equal versions break on
        // lexicographically greater SAID bytes.
        let expected_wp = if v1_a.said.as_ref() > v1_b.said.as_ref() {
            wp_a
        } else {
            wp_b
        };

        // Order 1: a then b
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier
            .verify_page(&[v0.clone(), v1_a.clone(), v1_b.clone()])
            .await
            .unwrap();
        let v1 = verifier.finish().await.unwrap();
        assert!(v1.policy_satisfied());
        assert_eq!(v1.write_policy(), &expected_wp);

        // Order 2: b then a — must return the same branch
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1_b, v1_a]).await.unwrap();
        let v2 = verifier.finish().await.unwrap();
        assert_eq!(v2.write_policy(), &expected_wp);
    }

    #[tokio::test]
    async fn test_rejected_same_write_policy() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Upd;
        v1.write_policy = None;
        v1.governance_policy = None;
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(RejectingChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(!verification.policy_satisfied());
    }

    #[tokio::test]
    async fn test_self_satisfies_failure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(RejectInceptionChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(!verification.policy_satisfied());
    }

    // ==================== Governance policy tests ====================

    #[tokio::test]
    async fn test_v0_with_governance_policy_valid() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_event().version, 0);
        assert_eq!(verification.establishment_version(), Some(0));
    }

    #[tokio::test]
    async fn test_v0_no_evaluation_v1_est_valid() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_governance_declaration(&mut v1);

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_event().version, 1);
        assert_eq!(verification.establishment_version(), Some(1));
    }

    #[tokio::test]
    async fn test_evaluation_overdue_at_64() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);

        let mut events = vec![v0.clone()];
        let mut current = v0.clone();
        // v1: Est (governance_policy declaration)
        current.content = Some(test_digest(b"content_1"));
        current.kind = SadEventKind::Est;
        current.write_policy = None;
        current.governance_policy = Some(test_digest(b"evaluation-policy"));
        current.increment().unwrap();
        events.push(current.clone());

        // v2..v63: 62 Upd events — within bound (1 Est + 62 Upd = 63 non-evaluation)
        current.kind = SadEventKind::Upd;
        current.governance_policy = None;
        for _ in 2..=63 {
            current.content = Some(test_digest(
                format!("content_{}", current.version + 1).as_bytes(),
            ));
            current.increment().unwrap();
            events.push(current.clone());
        }

        // v64 — should be rejected (overdue: 63 non-evaluation events, max is 63)
        current.content = Some(test_digest(b"content_64"));
        current.increment().unwrap();
        events.push(current.clone());

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&events).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("evaluation bound"),
            "Expected evaluation overdue error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_valid_evaluation_cycle() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);

        let mut events = vec![v0.clone()];
        let mut current = v0.clone();

        // v1: Est (governance_policy declaration, counts as non-evaluation)
        current.content = Some(test_digest(b"content_1"));
        add_governance_declaration(&mut current);
        events.push(current.clone());

        // v2..v63: 62 more Upd events (total 63 non-evaluation: v1..v63)
        current.kind = SadEventKind::Upd;
        current.write_policy = None;
        current.governance_policy = None;
        for i in 2..=63 {
            current.content = Some(test_digest(format!("content_{}", i).as_bytes()));
            current.increment().unwrap();
            events.push(current.clone());
        }

        // v64: first evaluation (resets counter)
        current.content = Some(test_digest(b"content_64"));
        add_governance_evaluation(&mut current);
        events.push(current.clone());

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&events).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_event().version, 64);
    }

    #[tokio::test]
    async fn test_governance_policy_evolution_on_evl_valid() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Evl;
        // Change governance_policy on an Evl event — valid (policy evolution)
        v1.governance_policy = Some(test_digest(b"new-evaluation-policy"));
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_event().version, 1);
    }

    #[tokio::test]
    async fn test_upd_with_governance_policy_rejected_by_validate_structure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Upd;
        // Upd must not set governance_policy — validate_structure rejects
        v1.governance_policy = Some(test_digest(b"new-evaluation-policy"));
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("must not have governancePolicy"),
            "Expected validate_structure error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_evl_without_governance_policy_on_branch_rejected() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Evl;
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("requires governance_policy to be established"),
            "Expected missing policy error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_chain_with_no_evaluation_rejected_at_finish() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Est;
        v1.write_policy = None;
        v1.governance_policy = Some(test_digest(b"evaluation-policy"));
        v1.increment().unwrap();

        // Chain has governance_policy established but never evaluated — still passes finish
        // (finish only checks that governance_policy exists on at least one branch)
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_event().version, 1);
    }

    #[tokio::test]
    async fn test_chain_with_no_governance_policy_at_all_rejected() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);

        // v0 without governance_policy and no Est — finish should reject
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("no governance_policy"),
            "Expected no governance_policy error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_v0_with_governance_policy_changes_prefix() {
        let wp = test_digest(b"write-policy");
        let v0_no_gp = create_v0_no_evaluation(wp);
        let v0_with_gp = create_v0_with_evaluation(wp);
        assert_ne!(v0_no_gp.prefix, v0_with_gp.prefix);
    }

    // ==================== Kind-specific chain-state tests ====================

    #[tokio::test]
    async fn test_est_at_v1_when_v0_had_no_evaluation_accepted() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_governance_declaration(&mut v1);

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_event().version, 1);
        assert_eq!(verification.establishment_version(), Some(1));
    }

    #[tokio::test]
    async fn test_est_at_v1_when_v0_declared_evaluation_rejected() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Est;
        v1.write_policy = None;
        v1.governance_policy = Some(test_digest(b"another-evaluation-policy"));
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("already established"),
            "Expected Est rejection, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_est_at_v2_rejected_by_validate_structure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_governance_declaration(&mut v1);

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.kind = SadEventKind::Est;
        v2.write_policy = None;
        v2.governance_policy = Some(test_digest(b"another-gp"));
        v2.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("Est event must have version 1"),
            "Expected version error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_upd_at_v1_when_v0_had_no_evaluation_rejected() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Upd;
        v1.write_policy = None;
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("requires governance_policy to be established"),
            "Expected governance_policy error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_rpr_evaluates_governance_policy() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Rpr;
        v1.write_policy = None;
        v1.governance_policy = None; // Rpr forbids governance_policy
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.last_governance_version(), Some(1));
    }

    #[tokio::test]
    async fn test_rpr_with_governance_policy_rejected_by_validate_structure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Rpr;
        v1.write_policy = None;
        v1.governance_policy = Some(test_digest(b"rpr-gp"));
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("must not have governancePolicy"),
            "Expected validate_structure error, got: {}",
            err
        );
    }

    // ==================== Evaluation tracking tests ====================

    #[tokio::test]
    async fn test_last_governance_version_tracked() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_governance_declaration(&mut v1);

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        add_governance_evaluation(&mut v2);

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.last_governance_version(), Some(2));
    }

    #[tokio::test]
    async fn test_last_governance_version_advances_past_first_evl_on_linear_chain() {
        // Regression: pre-fix, the chain-wide min() logic pinned
        // last_governance_version to the FIRST Evl's version and never advanced.
        // Chain: v0 Icp → v1 Est → v2 Evl → v3 Upd → v4 Evl.
        // Expected: last_governance_version == Some(4) (the most recent Evl).
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);

        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_governance_declaration(&mut v1);

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        add_governance_evaluation(&mut v2);

        let mut v3 = v2.clone();
        v3.content = Some(test_digest(b"content3"));
        v3.kind = SadEventKind::Upd;
        v3.write_policy = None;
        v3.governance_policy = None;
        v3.increment().unwrap();

        let mut v4 = v3.clone();
        v4.content = Some(test_digest(b"content4"));
        add_governance_evaluation(&mut v4);

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1, v2, v3, v4]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.last_governance_version(), Some(4));
    }

    #[tokio::test]
    async fn test_last_governance_version_none_without_evaluation() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        add_governance_declaration(&mut v1);

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.last_governance_version(), None);
    }

    #[tokio::test]
    async fn test_v0_non_icp_rejected_by_validate_structure() {
        let wp = test_digest(b"write-policy");
        let gp = test_digest(b"evaluation-policy");
        // Manually construct a v0 with Evl kind — should fail validate_structure
        let mut v0 = SadEvent {
            said: cesr::Digest256::default(),
            prefix: cesr::Digest256::default(),
            previous: None,
            version: 0,
            topic: "kels/sad/v1/keys/mlkem".to_string(),
            kind: SadEventKind::Evl,
            content: None,
            custody: None,
            write_policy: Some(wp),
            governance_policy: Some(gp),
        };
        v0.derive_said().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("Evl event must have version >= 1"),
            "Expected validate_structure error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_evaluation_after_est_accepted() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_no_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Est;
        v1.write_policy = None;
        v1.governance_policy = Some(test_digest(b"evaluation-policy"));
        v1.increment().unwrap();

        let mut v2 = v1.clone();
        v2.content = Some(test_digest(b"content2"));
        v2.kind = SadEventKind::Evl;
        v2.governance_policy = None;
        v2.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.current_event().version, 2);
    }

    #[tokio::test]
    async fn test_governance_policy_evaluation_failure() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Evl;
        v1.governance_policy = None;
        v1.increment().unwrap();

        // RejectingChecker returns Ok(false) for all satisfies calls —
        // governance_policy evaluation is a hard error (unlike write_policy which is soft).
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(RejectingChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("governance policy not satisfied"),
            "Expected governance policy error, got: {}",
            err
        );
    }

    // ==================== Divergence tracking + resume refusal ====================

    /// A linear chain must leave `diverged_at_version == None`.
    #[tokio::test]
    async fn test_diverged_at_version_none_on_linear_chain() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);
        let mut v1 = v0.clone();
        v1.content = Some(test_digest(b"content1"));
        v1.kind = SadEventKind::Upd;
        v1.write_policy = None;
        v1.governance_policy = None;
        v1.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.diverged_at_version(), None);
    }

    /// Two events at v1 extending the same v0 tip → diverged_at_version == Some(1).
    #[tokio::test]
    async fn test_diverged_at_version_set_at_first_fork() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);

        let mut v1_a = v0.clone();
        v1_a.content = Some(test_digest(b"content_a"));
        v1_a.kind = SadEventKind::Upd;
        v1_a.write_policy = None;
        v1_a.governance_policy = None;
        v1_a.increment().unwrap();

        let mut v1_b = v0.clone();
        v1_b.content = Some(test_digest(b"content_b"));
        v1_b.kind = SadEventKind::Upd;
        v1_b.write_policy = None;
        v1_b.governance_policy = None;
        v1_b.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&[v0, v1_a, v1_b]).await.unwrap();
        // `is_divergent()` only reports true once `finish()` flushes the last
        // generation — v1's fork is still in `generation_buffer` at this point.
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.diverged_at_version(), Some(1));
    }

    /// Once set, `diverged_at_version` doesn't advance on subsequent generations.
    /// Chain: v0 Icp → v1 two-branch fork → v2 (one event per branch).
    #[tokio::test]
    async fn test_diverged_at_version_set_once() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);

        let mut v1_a = v0.clone();
        v1_a.content = Some(test_digest(b"content_a"));
        v1_a.kind = SadEventKind::Upd;
        v1_a.write_policy = None;
        v1_a.governance_policy = None;
        v1_a.increment().unwrap();

        let mut v1_b = v0.clone();
        v1_b.content = Some(test_digest(b"content_b"));
        v1_b.kind = SadEventKind::Upd;
        v1_b.write_policy = None;
        v1_b.governance_policy = None;
        v1_b.increment().unwrap();

        // v2 on each branch — legitimate per-branch continuation, not new divergence.
        let mut v2_a = v1_a.clone();
        v2_a.content = Some(test_digest(b"content_a2"));
        v2_a.increment().unwrap();

        let mut v2_b = v1_b.clone();
        v2_b.content = Some(test_digest(b"content_b2"));
        v2_b.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier
            .verify_page(&[v0, v1_a, v1_b, v2_a, v2_b])
            .await
            .unwrap();
        let verification = verifier.finish().await.unwrap();
        assert_eq!(verification.diverged_at_version(), Some(1));
    }

    /// `SelVerifier::resume` must refuse tokens carrying a divergence marker.
    /// The single-branch rehydration cannot reconstruct the losing branch, so
    /// continuing from a divergent token would silently drop state.
    #[tokio::test]
    async fn test_resume_refuses_divergent_token() {
        let wp = test_digest(b"write-policy");
        let v0 = create_v0_with_evaluation(wp);

        let mut v1_a = v0.clone();
        v1_a.content = Some(test_digest(b"content_a"));
        v1_a.kind = SadEventKind::Upd;
        v1_a.write_policy = None;
        v1_a.governance_policy = None;
        v1_a.increment().unwrap();

        let mut v1_b = v0.clone();
        v1_b.content = Some(test_digest(b"content_b"));
        v1_b.kind = SadEventKind::Upd;
        v1_b.write_policy = None;
        v1_b.governance_policy = None;
        v1_b.increment().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier
            .verify_page(&[v0.clone(), v1_a, v1_b])
            .await
            .unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(verification.diverged_at_version().is_some());

        match SelVerifier::resume(&verification, Arc::clone(&checker)) {
            Err(KelsError::CannotResumeDivergentChain) => {}
            Err(e) => panic!("Expected CannotResumeDivergentChain, got: {e:?}"),
            Ok(_) => panic!("Expected resume to refuse divergent token"),
        }
    }
}
