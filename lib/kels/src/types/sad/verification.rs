//! SAD Event Log verification.
//!
//! Streaming structural + cross-chain authorization verifier for SAD Event
//! Logs. Round-12 shape: chains are identity-rooted and bound to a specific
//! Identity Event Log (IEL) via `event.identity` (set at Icp) and
//! `event.identity_event` (set at v1+). Authorization for v1+ events is
//! resolved by walking the bound IEL event via [`IelResolver`] — `Upd`
//! evaluates against `auth_policy`, `Sea` / `Rpr` / `Cnt` / `Dec` against
//! `governance_policy`. Mirrors `IelVerifier` in shape (page-by-page
//! processing, per-branch state, `resume` for re-hydration).
//!
//! Soft / hard mapping (mirrors `lib/kels/src/types/iel/verification.rs`
//! §"Soft-fail policy"):
//!
//! - **Icp** is permissionless — no anchor check; the chain cannot advance
//!   past Icp without satisfying the IEL-resolved `auth_policy`, so the
//!   permissionless prefix grants no authority on its own.
//! - **Upd** auth check is **HARD** — content advancement; same role as
//!   IEL `Evl` on IEL. Failure aborts verification.
//! - **Sea** / **Rpr** governance check is **HARD** — privileged-authority
//!   advancement events.
//! - **Cnt** / **Dec** governance check is **SOFT** — terminal forensic
//!   preservation; flags are content-based; auth status conveyed via
//!   `policy_satisfied`.
//! - `BadIdentityBinding` (binding doesn't resolve / prefix mismatch) is
//!   **HARD** for all v1+ kinds — chain integrity beats forensic preservation.
//! - `IelDivergent` (binding lives on an unstable IEL branch) is **HARD**
//!   for `Upd` / `Sea` / `Rpr`, **SOFT** for `Cnt` / `Dec`.
//! - Monotonic ratchet regression is **HARD** for all kinds (chain integrity).
//! - Content preservation (`Sea` / `Rpr` / `Cnt` / `Dec` carry `previous.content`
//!   forward unchanged) is **HARD** (structural).
//!
//! Terminal flags (`is_contested` / `is_decommissioned`) are set
//! unconditionally on any landed `Cnt` / `Dec`, regardless of whether the
//! terminating event passed its governance anchor check. The auth status
//! is conveyed separately via `policy_satisfied`. This mirrors the
//! round-11 IEL fix that pinned terminal flags to chain content.

use std::{collections::HashMap, sync::Arc};

use verifiable_storage::{Chained, SelfAddressed};

use super::event::{SadBranchTip, SadEvent, SadEventKind, SelVerification};
use crate::{
    KelsError,
    types::{IelResolver, PolicyChecker},
};

/// Streaming structural + cross-chain authorization verifier for SAD Event
/// Logs.
///
/// Mirrors `IelVerifier`. Tracks per-branch state in a HashMap keyed by tip
/// SAID; processes events page by page, generation by generation; produces
/// `SelVerification` on `finish`. `resume` re-hydrates from a prior token.
///
/// Events must arrive in `(version ASC, kind sort_priority ASC, said ASC)`
/// order — the canonical chain ordering used by every storage and transfer
/// path.
pub struct SelVerifier {
    prefix: Option<cesr::Digest256>,
    topic: Option<String>,
    /// Branches keyed by tip SAID. One entry on linear chains; two on divergent.
    branches: HashMap<cesr::Digest256, SadBranchTip>,
    /// Events buffered for the current generation (same version).
    generation_buffer: Vec<SadEvent>,
    /// The version of the current buffered generation.
    current_generation_version: Option<u64>,
    saw_any_events: bool,
    policy_satisfied: bool,
    is_contested: bool,
    is_decommissioned: bool,
    diverged_at_version: Option<u64>,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    iel_resolver: Arc<dyn IelResolver + Send + Sync>,
}

impl SelVerifier {
    pub fn new(
        prefix: Option<&cesr::Digest256>,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
        iel_resolver: Arc<dyn IelResolver + Send + Sync>,
    ) -> Self {
        Self {
            prefix: prefix.copied(),
            topic: None,
            branches: HashMap::new(),
            generation_buffer: Vec::new(),
            current_generation_version: None,
            saw_any_events: false,
            policy_satisfied: true,
            is_contested: false,
            is_decommissioned: false,
            diverged_at_version: None,
            checker,
            iel_resolver,
        }
    }

    /// Re-hydrate a verifier from a prior verification token. Subsequent
    /// `verify_page` calls extend the same per-branch state — including
    /// each branch's `last_identity_event` ratchet.
    pub fn resume(
        verification: &SelVerification,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
        iel_resolver: Arc<dyn IelResolver + Send + Sync>,
    ) -> Result<Self, KelsError> {
        let mut branches: HashMap<cesr::Digest256, SadBranchTip> = HashMap::new();
        for branch in verification.branches() {
            branches.insert(branch.tip.said, branch.clone());
        }

        let prefix = *verification.prefix();
        let topic = verification.topic().to_string();

        Ok(Self {
            prefix: Some(prefix),
            topic: Some(topic),
            branches,
            generation_buffer: Vec::new(),
            current_generation_version: None,
            saw_any_events: !verification.branches().is_empty(),
            policy_satisfied: verification.policy_satisfied(),
            is_contested: verification.is_contested(),
            is_decommissioned: verification.is_decommissioned(),
            diverged_at_version: verification.diverged_at_version(),
            checker,
            iel_resolver,
        })
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

        // Structural validation first.
        for event in &events {
            event
                .validate_structure()
                .map_err(KelsError::VerificationFailed)?;
        }

        if self.branches.is_empty() {
            // First generation — must be a single Icp at v0. Permissionless;
            // no anchor / immunity check (round-12 inception is granted no
            // authority on its own — the chain cannot advance past Icp
            // without satisfying the IEL-resolved auth_policy at v1).
            if events.len() != 1 {
                return Err(KelsError::VerificationFailed(
                    "Multiple events at version 0 — SE v0 divergence is not permitted".into(),
                ));
            }
            let event = &events[0];
            if version != 0 {
                return Err(KelsError::VerificationFailed(format!(
                    "First SE generation must be at version 0, got {}",
                    version
                )));
            }
            if event.kind != SadEventKind::Icp {
                return Err(KelsError::VerificationFailed(format!(
                    "First SE event must be Icp, got {}",
                    event.kind
                )));
            }
            event.verify_prefix()?;

            let identity = event.identity.ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "SE Icp {} missing required `identity` field",
                    event.said
                ))
            })?;

            self.branches.insert(
                event.said,
                SadBranchTip {
                    tip: event.clone(),
                    identity,
                    last_identity_event: None,
                    events_since_evaluation: 0,
                    last_governance_version: None,
                },
            );

            if self.prefix.is_none() {
                self.prefix = Some(event.prefix);
            }
            return Ok(());
        }

        // Max 2 events per generation post-Icp (one per branch).
        if events.len() > 2 {
            return Err(KelsError::VerificationFailed(format!(
                "SE generation at version {} has {} events, max 2 allowed",
                version,
                events.len()
            )));
        }

        // Detect divergence: more events than branches at this version means
        // a fork landed.
        if events.len() > self.branches.len() && self.diverged_at_version.is_none() {
            self.diverged_at_version = Some(version);
        }

        // Pre-batch position fetch (plan §Authorization resolution step 0):
        // collect every v1+ `event.identity_event` plus each branch's
        // current `last_identity_event` (skip `None`), then fetch IEL
        // chain positions in one call. All branches share the same
        // `branch.identity` on a divergent chain (the Icp shared prefix);
        // we use the first branch's identity for the fetch.
        let identity = {
            #[allow(clippy::expect_used)]
            // Branch invariant: at least one branch (we just checked it's
            // non-empty above). All branches share the same `identity`
            // because Icp is shared on divergent chains.
            let branch = self
                .branches
                .values()
                .next()
                .expect("flush_generation post-Icp invariant: branches non-empty");
            branch.identity
        };

        let mut needed_saids: Vec<cesr::Digest256> = events
            .iter()
            .filter_map(|e| e.identity_event)
            .collect();
        for branch in self.branches.values() {
            if let Some(said) = branch.last_identity_event {
                needed_saids.push(said);
            }
        }
        // Deduplicate (the resolver is permitted to error on the whole batch
        // if any SAID is unresolvable; deduping reduces unnecessary repo hits).
        needed_saids.sort();
        needed_saids.dedup();
        let positions = self
            .iel_resolver
            .iel_chain_positions(&identity, &needed_saids)
            .await?;

        let mut new_branches: HashMap<cesr::Digest256, SadBranchTip> = HashMap::new();

        for event in &events {
            let previous = event.previous.as_ref().ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "Non-inception SE event {} has no previous event",
                    event.said
                ))
            })?;

            // Clone the branch state so we can mutate `self` (e.g.
            // `record_terminal_landing`) within this loop iteration without
            // tripping the borrow checker on the parent map.
            let branch = self
                .branches
                .get(previous)
                .ok_or_else(|| {
                    KelsError::VerificationFailed(format!(
                        "SE event {} previous {} does not match any branch tip",
                        event.said, previous
                    ))
                })?
                .clone();
            let branch = &branch;

            let expected_version = branch.tip.version + 1;
            if event.version != expected_version {
                return Err(KelsError::VerificationFailed(format!(
                    "SE event {} has version {} but expected {} (branch tip + 1)",
                    event.said, event.version, expected_version
                )));
            }

            // Content preservation: Sea / Rpr / Cnt / Dec carry `previous.content`
            // forward unchanged. Hard structural rule.
            if matches!(
                event.kind,
                SadEventKind::Sea | SadEventKind::Rpr | SadEventKind::Cnt | SadEventKind::Dec
            ) && event.content != branch.tip.content
            {
                return Err(KelsError::VerificationFailed(format!(
                    "SE {} event {} must preserve content (got {:?}, expected {:?})",
                    event.kind, event.said, event.content, branch.tip.content
                )));
            }

            // Resolve cross-chain authorization. Steps 1–4 from the plan.
            let identity_event_said = event.identity_event.ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "Non-inception SE event {} missing required `identity_event`",
                    event.said
                ))
            })?;

            let is_terminal = matches!(event.kind, SadEventKind::Cnt | SadEventKind::Dec);

            // Step 1 — fetch IEL event. BadIdentityBinding is HARD for all v1+ kinds.
            // The IelResolver impl returns errors for SAID-not-found / prefix-mismatch;
            // surface them directly.
            let _bound = self
                .iel_resolver
                .fetch_iel_event(&branch.identity, &identity_event_said)
                .await?;

            // Steps 2 + 3 — pick policy + apply divergence gate.
            let policy_resolution = match event.kind {
                SadEventKind::Upd => {
                    self.iel_resolver
                        .resolve_auth_policy_at(&branch.identity, &identity_event_said)
                        .await
                }
                SadEventKind::Sea
                | SadEventKind::Rpr
                | SadEventKind::Cnt
                | SadEventKind::Dec => {
                    self.iel_resolver
                        .resolve_governance_policy_at(&branch.identity, &identity_event_said)
                        .await
                }
                SadEventKind::Icp => unreachable!("Icp handled in first-generation branch above"),
            };

            // IelDivergent: HARD for Upd/Sea/Rpr; SOFT for Cnt/Dec.
            let resolved_policy = match policy_resolution {
                Ok(p) => p,
                Err(KelsError::IelDivergent(_msg)) if is_terminal => {
                    // SOFT: the terminal event lands; mark policy_satisfied=false;
                    // terminal flag is set content-based below (unconditionally).
                    self.policy_satisfied = false;
                    self.record_terminal_landing(event, &mut new_branches, branch, false);
                    continue;
                }
                Err(e) => return Err(e),
            };

            // Step 4 — anchor check. HARD for Upd/Sea/Rpr; SOFT for Cnt/Dec.
            let anchored = self
                .checker
                .is_anchored(&event.said, &resolved_policy)
                .await?;

            if !anchored {
                if is_terminal {
                    self.policy_satisfied = false;
                    self.record_terminal_landing(event, &mut new_branches, branch, false);
                    continue;
                } else {
                    return Err(KelsError::VerificationFailed(format!(
                        "SE {} event {} not anchored under resolved policy {} \
                         (bound IEL event {})",
                        event.kind, event.said, resolved_policy, identity_event_said,
                    )));
                }
            }

            // Step 5 — monotonic ratchet (uses positions fetched above). HARD
            // for all kinds.
            let new_position = positions.get(&identity_event_said).ok_or_else(|| {
                KelsError::VerificationFailed(format!(
                    "SE event {} identity_event {} missing from prefetched IEL positions \
                     (resolver invariant breach)",
                    event.said, identity_event_said,
                ))
            })?;

            let new_last_identity_event = match branch.last_identity_event {
                None => {
                    // First-set path: hard-passed steps 1–4 means we ratchet.
                    Some(identity_event_said)
                }
                Some(prior_said) => {
                    let prior_position = positions.get(&prior_said).ok_or_else(|| {
                        KelsError::VerificationFailed(format!(
                            "Branch's prior last_identity_event {} missing from prefetched \
                             IEL positions (resolver invariant breach)",
                            prior_said,
                        ))
                    })?;
                    use std::cmp::Ordering;
                    match new_position.try_cmp(prior_position) {
                        Ok(Ordering::Less) => {
                            return Err(KelsError::BadIdentityBinding(format!(
                                "SE event {} identity_event {} regresses prior ratchet {} \
                                 in IEL chain order (monotonic)",
                                event.said, identity_event_said, prior_said,
                            )));
                        }
                        Ok(Ordering::Equal) => Some(prior_said),
                        Ok(Ordering::Greater) => Some(identity_event_said),
                        Err(_iel_divergent_unreachable) => {
                            // Defense-in-depth: structurally unreachable given
                            // the precondition that ratchet only updates after
                            // hard-pass on steps 1–4 (so we never feed
                            // post-divergence-different-branch positions).
                            // If we get here, chain integrity has been breached;
                            // hard-fail uniformly with the same monotonic
                            // surface as Less (the trait contract specifies
                            // BadIdentityBinding for the chain-integrity
                            // umbrella).
                            return Err(KelsError::BadIdentityBinding(format!(
                                "SE event {} identity_event {} compares as IelDivergent \
                                 against prior ratchet {} (monotonic — chain integrity breach)",
                                event.said, identity_event_said, prior_said,
                            )));
                        }
                    }
                }
            };

            // Step 6 — apply per-kind chain-state advancement.
            let (new_last_governance_version, new_events_since_evaluation) = match event.kind {
                SadEventKind::Upd => {
                    // Non-evaluation event; counter advances.
                    (branch.last_governance_version, branch.events_since_evaluation + 1)
                }
                SadEventKind::Sea | SadEventKind::Rpr => {
                    // Authorized governance evaluation; advances seal,
                    // resets counter.
                    (Some(event.version), 0)
                }
                SadEventKind::Cnt | SadEventKind::Dec => {
                    // Terminal HARD-passed paths land here. Cnt/Dec do NOT
                    // advance the seal but DO set the terminal flag.
                    if event.kind.is_contest() {
                        self.is_contested = true;
                    } else {
                        self.is_decommissioned = true;
                    }
                    (branch.last_governance_version, branch.events_since_evaluation)
                }
                SadEventKind::Icp => unreachable!("Icp handled above"),
            };

            new_branches.insert(
                event.said,
                SadBranchTip {
                    tip: event.clone(),
                    identity: branch.identity,
                    last_identity_event: new_last_identity_event,
                    events_since_evaluation: new_events_since_evaluation,
                    last_governance_version: new_last_governance_version,
                },
            );
        }

        // Carry forward branches no event in this generation extended.
        for (said, state) in &self.branches {
            if !events.iter().any(|e| e.previous.as_ref() == Some(said)) {
                new_branches.insert(*said, state.clone());
            }
        }

        self.branches = new_branches;
        Ok(())
    }

    /// Record a SOFT-passed terminal event (Cnt/Dec that failed its
    /// IelDivergent guard or anchor check). The event lands on the chain
    /// (replaces the parent branch tip) and sets the appropriate terminal
    /// flag content-based, but does NOT advance `last_identity_event`,
    /// `last_governance_version`, or `events_since_evaluation` — per the
    /// "Update precondition" rule that keeps the ratchet pinned to a
    /// known-clean position.
    fn record_terminal_landing(
        &mut self,
        event: &SadEvent,
        new_branches: &mut HashMap<cesr::Digest256, SadBranchTip>,
        parent: &SadBranchTip,
        _hard_passed: bool,
    ) {
        if event.kind.is_contest() {
            self.is_contested = true;
        } else {
            self.is_decommissioned = true;
        }
        new_branches.insert(
            event.said,
            SadBranchTip {
                tip: event.clone(),
                identity: parent.identity,
                last_identity_event: parent.last_identity_event,
                events_since_evaluation: parent.events_since_evaluation,
                last_governance_version: parent.last_governance_version,
            },
        );
    }

    /// Verify a page of events. Events must arrive in
    /// `(version ASC, kind sort_priority ASC, said ASC)` order with complete
    /// generations within the page.
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

    /// Finish verification and produce the proof token.
    pub async fn finish(mut self) -> Result<SelVerification, KelsError> {
        self.flush_generation().await?;

        if !self.saw_any_events {
            return Err(KelsError::VerificationFailed(
                "SelVerifier::finish: no events were verified".into(),
            ));
        }
        if self.branches.is_empty() {
            return Err(KelsError::VerificationFailed(
                "No tip after SE verification".into(),
            ));
        }

        let mut branches: Vec<SadBranchTip> = self.branches.into_values().collect();
        branches.sort_by_key(|b| b.tip.said);

        let last_governance_version = branches
            .iter()
            .filter_map(|b| b.last_governance_version)
            .max();

        Ok(SelVerification::new(
            branches,
            self.policy_satisfied,
            self.is_contested,
            self.is_decommissioned,
            last_governance_version,
            self.diverged_at_version,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use crate::types::{IdentityEvent, IdentityEventKind, IelChainPosition};

    const TEST_TOPIC: &str = "kels/sad/v1/keys/mlkem";

    fn d(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    // ==================== Test fakes ====================

    /// `PolicyChecker` that always returns `Ok(true)`.
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

    /// `PolicyChecker` that returns `Ok(false)` (not anchored) for SAIDs in a
    /// reject-list, `Ok(true)` otherwise. Used to drive soft/hard fail cases
    /// per kind.
    struct RejectingChecker {
        reject: HashSet<cesr::Digest256>,
    }
    #[async_trait::async_trait]
    impl PolicyChecker for RejectingChecker {
        async fn is_anchored(
            &self,
            said: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<bool, KelsError> {
            Ok(!self.reject.contains(said))
        }
        async fn is_immune(&self, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    /// Configurable IEL resolver fake. Holds a SAID-keyed map of fake IEL
    /// events with `(version, auth_policy, governance_policy, kind)` and an
    /// optional divergence threshold (`first_divergent_version`).
    #[derive(Clone)]
    struct FakeIelResolver {
        identity: cesr::Digest256,
        events: HashMap<cesr::Digest256, FakeIelEntry>,
        first_divergent_version: Option<u64>,
    }

    #[derive(Clone)]
    struct FakeIelEntry {
        version: u64,
        kind: IdentityEventKind,
        auth_policy: cesr::Digest256,
        governance_policy: cesr::Digest256,
    }

    impl FakeIelResolver {
        fn new(identity: cesr::Digest256) -> Self {
            Self {
                identity,
                events: HashMap::new(),
                first_divergent_version: None,
            }
        }

        fn with_event(
            mut self,
            said: cesr::Digest256,
            version: u64,
            kind: IdentityEventKind,
            auth_policy: cesr::Digest256,
            governance_policy: cesr::Digest256,
        ) -> Self {
            self.events.insert(
                said,
                FakeIelEntry {
                    version,
                    kind,
                    auth_policy,
                    governance_policy,
                },
            );
            self
        }

        fn with_divergence_at(mut self, version: u64) -> Self {
            self.first_divergent_version = Some(version);
            self
        }
    }

    #[async_trait::async_trait]
    impl IelResolver for FakeIelResolver {
        async fn fetch_iel_event(
            &self,
            identity: &cesr::Digest256,
            said: &cesr::Digest256,
        ) -> Result<IdentityEvent, KelsError> {
            if identity != &self.identity {
                return Err(KelsError::BadIdentityBinding(format!(
                    "FakeIelResolver: identity mismatch (got {}, expected {})",
                    identity, self.identity
                )));
            }
            let entry = self.events.get(said).ok_or_else(|| {
                KelsError::BadIdentityBinding(format!(
                    "FakeIelResolver: no event for SAID {}",
                    said
                ))
            })?;
            // Build a synthetic IEL event with the recorded fields. SAID/prefix
            // wired up to be self-consistent for the verifier's checks (we
            // don't go through `IdentityEvent::icp` since that derives prefix
            // from auth/gov/topic — we want exact control).
            Ok(IdentityEvent {
                said: *said,
                prefix: self.identity,
                previous: None,
                version: entry.version,
                topic: "iel-fake".to_string(),
                kind: entry.kind,
                auth_policy: entry.auth_policy,
                governance_policy: entry.governance_policy,
            })
        }

        async fn resolve_auth_policy_at(
            &self,
            identity: &cesr::Digest256,
            said: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            let event = self.fetch_iel_event(identity, said).await?;
            if let Some(divergent) = self.first_divergent_version
                && event.version >= divergent
            {
                return Err(KelsError::IelDivergent(format!(
                    "FakeIelResolver: event {} at version {} is at-or-after divergence {}",
                    said, event.version, divergent
                )));
            }
            Ok(event.auth_policy)
        }

        async fn resolve_governance_policy_at(
            &self,
            identity: &cesr::Digest256,
            said: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            let event = self.fetch_iel_event(identity, said).await?;
            if let Some(divergent) = self.first_divergent_version
                && event.version >= divergent
            {
                return Err(KelsError::IelDivergent(format!(
                    "FakeIelResolver: event {} at version {} is at-or-after divergence {}",
                    said, event.version, divergent
                )));
            }
            Ok(event.governance_policy)
        }

        async fn iel_chain_positions(
            &self,
            identity: &cesr::Digest256,
            saids: &[cesr::Digest256],
        ) -> Result<HashMap<cesr::Digest256, IelChainPosition>, KelsError> {
            if identity != &self.identity {
                return Err(KelsError::BadIdentityBinding(format!(
                    "FakeIelResolver: identity mismatch (got {}, expected {})",
                    identity, self.identity
                )));
            }
            let mut out = HashMap::new();
            for said in saids {
                let entry = self.events.get(said).ok_or_else(|| {
                    KelsError::BadIdentityBinding(format!(
                    "FakeIelResolver: no event for SAID {}",
                    said
                ))
                })?;
                let branch_marker = match self.first_divergent_version {
                    Some(d) if entry.version >= d => Some(*said),
                    _ => None,
                };
                out.insert(
                    *said,
                    IelChainPosition {
                        version: entry.version,
                        kind: entry.kind,
                        said: *said,
                        branch_marker,
                    },
                );
            }
            Ok(out)
        }
    }

    fn fake_resolver_for_chain(
        identity: cesr::Digest256,
        events: &[(cesr::Digest256, u64, IdentityEventKind)],
        auth_policy: cesr::Digest256,
        gov_policy: cesr::Digest256,
    ) -> FakeIelResolver {
        let mut r = FakeIelResolver::new(identity);
        for (said, version, kind) in events {
            r = r.with_event(*said, *version, *kind, auth_policy, gov_policy);
        }
        r
    }

    fn always_pass() -> Arc<dyn PolicyChecker + Send + Sync> {
        Arc::new(AlwaysPassChecker)
    }

    fn rejecting(saids: &[cesr::Digest256]) -> Arc<dyn PolicyChecker + Send + Sync> {
        Arc::new(RejectingChecker {
            reject: saids.iter().copied().collect(),
        })
    }

    // ==================== Helpers to build SE chains ====================

    fn make_icp(identity: cesr::Digest256) -> SadEvent {
        SadEvent::icp(TEST_TOPIC, identity).unwrap()
    }

    fn make_upd(prev: &SadEvent, iel_evt: cesr::Digest256, content_label: &[u8]) -> SadEvent {
        SadEvent::upd(prev, iel_evt, d(content_label)).unwrap()
    }

    // ==================== Tests ====================

    /// Linear chain `[Icp, Upd]` with Upd binding to IEL Icp; expect
    /// `policy_satisfied=true`, branch ratchet visible, no terminal flags.
    #[tokio::test]
    async fn linear_chain_icp_upd_with_iel_icp_binding() {
        let identity = d(b"identity-A");
        let iel_icp = d(b"iel-icp-said");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-policy-A"),
            d(b"gov-policy-A"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"content-1");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.policy_satisfied());
        assert!(!v.is_contested());
        assert!(!v.is_decommissioned());
        assert_eq!(v.diverged_at_version(), None);
        assert_eq!(v.branches().len(), 1);
        let branch = &v.branches()[0];
        assert_eq!(branch.identity, identity);
        assert_eq!(branch.last_identity_event, Some(iel_icp));
    }

    /// Upd binding to a later IEL Evl after IEL evolution: ratchet advances.
    #[tokio::test]
    async fn upd_binding_to_later_iel_evl_advances_ratchet() {
        let identity = d(b"identity-B");
        let iel_icp = d(b"iel-icp-B");
        let iel_evl = d(b"iel-evl-B");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[
                (iel_icp, 0, IdentityEventKind::Icp),
                (iel_evl, 1, IdentityEventKind::Evl),
            ],
            d(b"auth-B"),
            d(b"gov-B"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let v2 = make_upd(&v1, iel_evl, b"c2");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.policy_satisfied());
        assert_eq!(v.branches()[0].last_identity_event, Some(iel_evl));
    }

    /// `event.identity_event` referencing an unknown SAID → `BadIdentityBinding`-class
    /// error from the resolver. Currently surfaced as `InvalidIel` (per Gap 0
    /// deviation; Gap 6 introduces the variant).
    ///
    /// Errors fire at `finish()` because the verifier buffers per-generation
    /// (see `SelVerifier::flush_generation`) — `verify_page` only flushes
    /// when the version changes. Tests below follow the same pattern.
    #[tokio::test]
    async fn upd_with_unknown_identity_event_rejects() {
        let identity = d(b"identity-C");
        let iel_icp = d(b"iel-icp-C");
        let unknown = d(b"unknown-iel-event");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-C"),
            d(b"gov-C"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, unknown, b"c1");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            matches!(err, KelsError::BadIdentityBinding(_)),
            "expected BadIdentityBinding, got {err:?}"
        );
    }

    /// `event.identity_event` regresses ratchet (older IEL event after newer)
    /// → HARD reject. Reuses the same resolver across two IEL events.
    #[tokio::test]
    async fn upd_with_regressing_ratchet_rejected() {
        let identity = d(b"identity-D");
        let iel_icp = d(b"iel-icp-D");
        let iel_evl = d(b"iel-evl-D");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[
                (iel_icp, 0, IdentityEventKind::Icp),
                (iel_evl, 1, IdentityEventKind::Evl),
            ],
            d(b"auth-D"),
            d(b"gov-D"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        // v1 binds to the LATER IEL Evl, ratcheting the branch forward.
        let v1 = make_upd(&v0, iel_evl, b"c1");
        // v2 binds to the EARLIER IEL Icp, regressing → reject.
        let v2 = make_upd(&v1, iel_icp, b"c2");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            matches!(err, KelsError::BadIdentityBinding(_))
                && err.to_string().contains("regresses prior ratchet"),
            "expected BadIdentityBinding(monotonic), got {err:?}"
        );
    }

    /// HARD `Upd` anchor failure: chain does not advance (replaces today's
    /// soft-Upd behavior).
    #[tokio::test]
    async fn upd_rejects_when_anchor_check_fails() {
        let identity = d(b"identity-E");
        let iel_icp = d(b"iel-icp-E");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-E"),
            d(b"gov-E"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let checker = rejecting(&[v1.said]);

        let mut verifier = SelVerifier::new(Some(&v0.prefix), checker, resolver);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("not anchored"),
            "expected hard anchor-failure error, got {err}"
        );
    }

    /// Upd binding to a divergent-IEL post-divergence event: HARD reject
    /// (advancement events cannot rest on unstable IEL state).
    #[tokio::test]
    async fn upd_binding_to_divergent_iel_event_hard_rejects() {
        let identity = d(b"identity-F");
        let iel_evl = d(b"iel-evl-F");

        let resolver = Arc::new(
            FakeIelResolver::new(identity)
                .with_event(
                    iel_evl,
                    1,
                    IdentityEventKind::Evl,
                    d(b"auth-F"),
                    d(b"gov-F"),
                )
                .with_divergence_at(1),
        ) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_evl, b"c1");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            matches!(err, KelsError::IelDivergent(_)),
            "expected IelDivergent, got {err:?}"
        );
    }

    /// Cnt without governance auth lands; chain becomes contested;
    /// `policy_satisfied=false`. Pins the content-based-terminal-flag rule.
    #[tokio::test]
    async fn cnt_without_governance_auth_lands_with_policy_unsatisfied() {
        let identity = d(b"identity-G");
        let iel_icp = d(b"iel-icp-G");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-G"),
            d(b"gov-G"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let cnt = SadEvent::cnt(&v1, iel_icp).unwrap();
        let checker = rejecting(&[cnt.said]);

        let mut verifier = SelVerifier::new(Some(&v0.prefix), checker, resolver);
        verifier.verify_page(&[v0, v1, cnt]).await.unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.is_contested());
        assert!(!v.is_decommissioned());
        assert!(!v.policy_satisfied());
    }

    /// Dec without governance auth: same content-based-terminal-flag rule.
    #[tokio::test]
    async fn dec_without_governance_auth_lands_with_policy_unsatisfied() {
        let identity = d(b"identity-H");
        let iel_icp = d(b"iel-icp-H");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-H"),
            d(b"gov-H"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let dec = SadEvent::dec(&v1, iel_icp).unwrap();
        let checker = rejecting(&[dec.said]);

        let mut verifier = SelVerifier::new(Some(&v0.prefix), checker, resolver);
        verifier.verify_page(&[v0, v1, dec]).await.unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.is_decommissioned());
        assert!(!v.is_contested());
        assert!(!v.policy_satisfied());
    }

    /// Cnt binding to an IEL-divergent post-divergence event: SOFT-passes
    /// (lands; terminal flag content-based; `policy_satisfied=false`).
    #[tokio::test]
    async fn cnt_with_divergent_iel_binding_lands_softly() {
        let identity = d(b"identity-I");
        let iel_icp = d(b"iel-icp-I");
        let iel_evl_div = d(b"iel-evl-div-I");

        let resolver = Arc::new(
            FakeIelResolver::new(identity)
                .with_event(
                    iel_icp,
                    0,
                    IdentityEventKind::Icp,
                    d(b"auth-I"),
                    d(b"gov-I"),
                )
                .with_event(
                    iel_evl_div,
                    1,
                    IdentityEventKind::Evl,
                    d(b"auth-I"),
                    d(b"gov-I"),
                )
                .with_divergence_at(1),
        ) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let cnt = SadEvent::cnt(&v1, iel_evl_div).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, cnt]).await.unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.is_contested());
        assert!(!v.policy_satisfied());
        // Ratchet was set by v1 (hard-passed), but the soft-passed Cnt does
        // NOT advance it.
        assert_eq!(v.branches()[0].last_identity_event, Some(iel_icp));
    }

    /// Sea advances `last_governance_version` and ratchets `last_identity_event`.
    #[tokio::test]
    async fn sea_advances_seal_and_ratchet() {
        let identity = d(b"identity-J");
        let iel_icp = d(b"iel-icp-J");
        let iel_evl = d(b"iel-evl-J");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[
                (iel_icp, 0, IdentityEventKind::Icp),
                (iel_evl, 1, IdentityEventKind::Evl),
            ],
            d(b"auth-J"),
            d(b"gov-J"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let v2 = SadEvent::sea(&v1, iel_evl).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, v2]).await.unwrap();
        let v = verifier.finish().await.unwrap();

        assert_eq!(v.last_governance_version(), Some(2));
        assert_eq!(v.branches()[0].last_identity_event, Some(iel_evl));
        assert!(v.policy_satisfied());
    }

    /// Content preservation: Sea/Rpr/Cnt/Dec must carry `previous.content`
    /// forward unchanged. A tampered Sea is rejected as a structural error.
    #[tokio::test]
    async fn sea_tampering_with_content_rejected_structurally() {
        let identity = d(b"identity-K");
        let iel_icp = d(b"iel-icp-K");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-K"),
            d(b"gov-K"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let mut sea = SadEvent::sea(&v1, iel_icp).unwrap();
        // Tamper: replace content with a different SAID, and re-derive said
        // so it passes verify_said() but fails the content-preservation rule.
        sea.content = Some(d(b"tampered-content"));
        sea.derive_said().unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, sea]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            err.to_string().contains("preserve content"),
            "expected content-preservation error, got {err}"
        );
    }

    /// Resume preserves `last_identity_event` ratchet across page boundaries.
    #[tokio::test]
    async fn resume_preserves_ratchet_across_pages() {
        let identity = d(b"identity-L");
        let iel_icp = d(b"iel-icp-L");
        let iel_evl = d(b"iel-evl-L");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[
                (iel_icp, 0, IdentityEventKind::Icp),
                (iel_evl, 1, IdentityEventKind::Evl),
            ],
            d(b"auth-L"),
            d(b"gov-L"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");

        let mut verifier =
            SelVerifier::new(Some(&v0.prefix), always_pass(), Arc::clone(&resolver));
        verifier.verify_page(&[v0.clone(), v1.clone()]).await.unwrap();
        let token1 = verifier.finish().await.unwrap();
        assert_eq!(token1.branches()[0].last_identity_event, Some(iel_icp));

        // Resume from the token; verify page 2 carries the ratchet forward.
        let v2 = make_upd(&v1, iel_evl, b"c2");
        let mut verifier2 =
            SelVerifier::resume(&token1, always_pass(), Arc::clone(&resolver)).unwrap();
        verifier2.verify_page(&[v2]).await.unwrap();
        let token2 = verifier2.finish().await.unwrap();
        assert_eq!(token2.branches()[0].last_identity_event, Some(iel_evl));
    }

    /// Pre-divergence shared IEL events resolve cleanly even when the IEL is
    /// divergent: an Upd binding to `iel_icp` (pre-divergence) succeeds even
    /// though the IEL has diverged at version 1.
    #[tokio::test]
    async fn pre_divergence_iel_event_resolves_cleanly() {
        let identity = d(b"identity-M");
        let iel_icp = d(b"iel-icp-M");
        let iel_evl_div = d(b"iel-evl-div-M");

        let resolver = Arc::new(
            FakeIelResolver::new(identity)
                .with_event(
                    iel_icp,
                    0,
                    IdentityEventKind::Icp,
                    d(b"auth-M"),
                    d(b"gov-M"),
                )
                .with_event(
                    iel_evl_div,
                    1,
                    IdentityEventKind::Evl,
                    d(b"auth-M"),
                    d(b"gov-M"),
                )
                .with_divergence_at(1),
        ) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let v = verifier.finish().await.unwrap();
        assert!(v.policy_satisfied());
    }
}
