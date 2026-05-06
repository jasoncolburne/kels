//! SAD Event Log verification.
//!
//! Streaming structural + cross-chain authorization verifier for SAD Event
//! Logs. #147: chains are identity-rooted and bound to a specific
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
//! - `MissingIelEvent` / `IdentityBindingViolation` (binding doesn't resolve / prefix mismatch) is
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
//! IEL fix that pinned terminal flags to chain content.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use verifiable_storage::{Chained, SelfAddressed};

use super::event::{SadBranchTip, SadEvent, SadEventKind, SelVerification};
use crate::{
    DeferredFailure, KelsError,
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
    queried_saids: BTreeSet<cesr::Digest256>,
    satisfied_saids: BTreeSet<cesr::Digest256>,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    iel_resolver: Arc<dyn IelResolver + Send + Sync>,
    /// #156 collect-mode: when `true`, deferrable failures
    /// (`MissingIelEvent`, `MissingKelAnchor`) accumulate into
    /// `deferred_failures` and the walk treats them as soft-fail-style
    /// (continue with `policy_satisfied=false`); when `false`,
    /// deferrables propagate as `Err(KelsError)` and halt the walk
    /// (legacy behavior). Permanent failures always halt.
    collecting: bool,
    /// #156: accumulated deferrable failures. Empty in strict mode.
    /// Caller reads after `finish_collecting` (or via `deferred_failures()`).
    deferred_failures: Vec<DeferredFailure>,
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
            queried_saids: BTreeSet::new(),
            satisfied_saids: BTreeSet::new(),
            checker,
            iel_resolver,
            collecting: false,
            deferred_failures: Vec::new(),
        }
    }

    /// Enable #156 collect-mode for this verifier. Deferrable failures
    /// (`MissingIelEvent`, `MissingKelAnchor`) accumulate instead of
    /// halting the walk. Permanent failures still halt. Idempotent;
    /// calling once is sufficient.
    pub fn enable_collecting(&mut self) -> &mut Self {
        self.collecting = true;
        self
    }

    /// Read accumulated deferrable failures (after running
    /// `verify_page_collecting`). Empty in strict mode.
    pub fn deferred_failures(&self) -> &[DeferredFailure] {
        &self.deferred_failures
    }

    /// Register SE event SAIDs the caller cares about for satisfaction
    /// tracking. Mirrors `KelVerifier::check_anchors`. Call before
    /// `verify_page` (or before resuming the walk via `resume`). Repeated
    /// calls union the sets — they don't replace.
    pub fn check_satisfied(
        &mut self,
        saids: impl IntoIterator<Item = cesr::Digest256>,
    ) -> &mut Self {
        self.queried_saids.extend(saids);
        self
    }

    /// Re-hydrate a verifier from a prior verification token. Subsequent
    /// `verify_page` calls extend the same per-branch state — including
    /// each branch's `last_identity_event` ratchet.
    ///
    /// Like the IEL parallel, rehydrates `queried_saids` / `satisfied_saids`
    /// from the prior token (KEL's `resume` resets these; the IEL/SE
    /// streaming pre-walk pattern needs them to persist across pages).
    /// KEL's symmetric fix is deferred to #161.
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
            queried_saids: verification.queried_saids().clone(),
            satisfied_saids: verification.satisfied_saids().clone(),
            checker,
            iel_resolver,
            collecting: false,
            deferred_failures: Vec::new(),
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
            // no anchor / immunity check (#147: inception is granted no
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

            // Satisfied-SAIDs tracking. SE Icp is permissionless (no anchor
            // check); landing means it satisfies the SE auth contract by
            // construction. v=0 is structurally pre-divergence.
            if self.queried_saids.contains(&event.said) {
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

        let mut needed_saids: Vec<cesr::Digest256> =
            events.iter().filter_map(|e| e.identity_event).collect();
        for branch in self.branches.values() {
            if let Some(said) = branch.last_identity_event {
                needed_saids.push(said);
            }
        }
        // Deduplicate (the resolver also dedups internally but we save one
        // `clone()` by deduping here too).
        needed_saids.sort();
        needed_saids.dedup();
        let position_batch = self
            .iel_resolver
            .iel_chain_positions(&identity, &needed_saids)
            .await?;
        // Per-event Step 3 (`is_satisfied`) is the authoritative deferrable
        // gate for missing IEL events; it sees each event's
        // `identity_event` in turn and routes through `IelSatisfaction`.
        // The position-batch's `missing` list is the same set seen from
        // the bulk-fetch side — strict mode hard-fails on the first miss
        // here so the chain-integrity error matches the legacy surface;
        // collect mode accumulates every miss and lets each affected event
        // soft-fail at Step 3.
        if !position_batch.missing.is_empty() {
            if self.collecting {
                for missing in &position_batch.missing {
                    self.deferred_failures
                        .push(DeferredFailure::missing_iel_event(identity, *missing));
                }
            } else if let Some(missing) = position_batch.missing.first() {
                return Err(KelsError::missing_iel_event(identity, *missing));
            }
        }

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

            // #171 divergent-chain gate (per-event), narrowed by
            // sealed-vs-unsealed: once a chain is divergent, the
            // legitimate resolver is determined by whether the
            // governance seal has advanced past the divergence point.
            // - **Unsealed-divergent** (`max_seal < div`): only `Rpr` —
            //   Rpr truncates the adversary branch and resolves cleanly.
            //   `Cnt` here is premature; the operator should `Rpr`.
            // - **Sealed-divergent** (`max_seal >= div`): only `Cnt` —
            //   `Rpr` cannot truncate behind the seal, so `Cnt` is the
            //   only legitimate move.
            // The divergence-creating events themselves (at
            // version == diverged_at_version) bypass this check; only
            // events at version > diverged_at_version are post-divergence.
            // See `docs/design/sel/event-log.md §Chain States`.
            if let Some(div_at) = self.diverged_at_version
                && event.version > div_at
            {
                let max_seal = self
                    .branches
                    .values()
                    .filter_map(|b| b.last_governance_version)
                    .max();
                let is_sealed_divergent = max_seal.is_some_and(|s| s >= div_at);
                let allowed = if is_sealed_divergent {
                    event.kind == SadEventKind::Cnt
                } else {
                    event.kind == SadEventKind::Rpr
                };
                if !allowed {
                    let (state_label, allowed_label) = if is_sealed_divergent {
                        ("sealed-divergent", "Cnt")
                    } else {
                        ("unsealed-divergent", "Rpr")
                    };
                    return Err(KelsError::VerificationFailed(format!(
                        "SE event {} ({}) cannot extend {} chain at version {} \
                         (only {} allowed post-divergence)",
                        event.said, event.kind, state_label, event.version, allowed_label
                    )));
                }
            }

            // #171 terminal-state gate: `Cnt` and `Dec` are tombstones —
            // extending either tip is structurally invalid. Cnt-supersedes-
            // Dec (Cnt forking from a pre-Dec ancestor to invalidate a
            // forced/coerced Dec) requires non-tip parent-lookup and is
            // deferred to #174; until then post-Dec rejects all
            // submissions including Cnt. Per-branch (not chain-wide): a
            // divergent chain with a terminal on one branch doesn't
            // invalidate independent extensions on another branch — those
            // extensions resolve `event.previous` to a non-terminal tip
            // and pass. See `docs/design/sel/event-log.md §Chain States`.
            if branch.tip.kind.is_terminal() {
                return Err(KelsError::VerificationFailed(format!(
                    "SE event {} cannot extend terminal {} {}",
                    event.said, branch.tip.kind, branch.tip.said
                )));
            }

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

            // Two distinct soft-fail rules govern the auth gates below; each
            // gate (IelDivergent, IEL-satisfied, anchor) consults their union.
            //
            //  1. **Terminal-soft** (baseline): Cnt/Dec auth-failures
            //     soft-fail under any chain state. Terminal flags are
            //     content-based; auth status surfaces via `policy_satisfied`.
            //     Mirrors `docs/design/sel/verification.md §Soft-fail policy`.
            //
            //  2. **Post-divergence-soft** (#147 follow-up): on
            //     SE chains where Cnt has structurally created divergence
            //     (`diverged_at_version <= event.version`), ALL v1+ kinds'
            //     auth-failures soft-fail. The chain is already invalidated
            //     by the terminal; further auth failures don't add information
            //     and bouncing the verification would lose pre-divergence
            //     reads. Mirrors `docs/design/sel/verification.md
            //     §Post-divergence soft-fail propagation`.
            //
            // Structural integrity rules (`MissingIelEvent`/`IdentityBindingViolation`, monotonic
            // ratchet, content preservation) stay HARD regardless of either
            // rule — Cnt doesn't change well-formedness.
            let terminal_soft = is_terminal;
            let post_divergence_soft = self.diverged_at_version.is_some_and(|d| event.version >= d);
            let auth_soft_eligible = terminal_soft || post_divergence_soft;

            // Per-event auth gate sequence (β-ordering, see
            // `docs/design/sel/verification.md §Caller-bounded SAID querying`):
            //
            //   1. fetch_iel_event              — chain integrity (HARD always).
            //   2. resolve_*_at                 — IelDivergent gate (severity per `auth_soft_eligible`).
            //   3. is_satisfied                 — IEL-side auth + divergence cutoff (severity per `auth_soft_eligible`).
            //   4. is_anchored                  — SE-side auth check (severity per `auth_soft_eligible`).
            //   5. monotonic-ratchet            — chain integrity (HARD always).
            //
            // Step 3 lands AFTER `resolve_*_at` so the existing IelDivergent
            // gate stays as defense-in-depth: `is_satisfied` covers the
            // auth-fail-pre-divergence case the divergence gate doesn't see;
            // `resolve_*_at` covers the divergence case `is_satisfied` could
            // also detect. Both gates remain wired to keep the soundness
            // surface explicit at each point of failure.

            // Step 1 — fetch IEL event. The IelResolver impl returns
            // `MissingIelEvent` (deferrable, post-#156) when the SAID
            // isn't local; `IdentityBindingViolation` (permanent) on
            // cross-IEL contamination / prefix mismatch. Strict mode
            // halts on either; collect-mode re-routes `MissingIelEvent`
            // through the deferrable accumulator with soft-fail-style
            // state advancement (`IdentityBindingViolation` always halts).
            match self
                .iel_resolver
                .fetch_iel_event(&branch.identity, &identity_event_said)
                .await
            {
                Ok(_) => {}
                Err(KelsError::MissingIelEvent(_)) if auth_soft_eligible => {
                    // Soft-eligible (terminal or post-SE-divergence):
                    // chain still lands; missing IEL event isn't accumulated
                    // — soft-fail is the intentional behavior.
                    self.policy_satisfied = false;
                    if is_terminal {
                        self.record_terminal_landing(event, &mut new_branches, branch, false);
                    } else {
                        Self::record_non_terminal_soft_landing(event, &mut new_branches, branch);
                    }
                    continue;
                }
                Err(KelsError::MissingIelEvent(dep)) if self.collecting => {
                    // HARD-mode collect path: accumulate + soft-fail-style.
                    self.deferred_failures
                        .push(DeferredFailure::missing_iel_event(
                            dep.iel_prefix,
                            dep.event_said,
                        ));
                    self.policy_satisfied = false;
                    Self::record_non_terminal_soft_landing(event, &mut new_branches, branch);
                    continue;
                }
                Err(e) => return Err(e),
            }

            // Steps 2 + 3 — pick policy + apply divergence gate.
            let policy_resolution = match event.kind {
                SadEventKind::Upd => {
                    self.iel_resolver
                        .resolve_auth_policy_at(&branch.identity, &identity_event_said)
                        .await
                }
                SadEventKind::Sea | SadEventKind::Rpr | SadEventKind::Cnt | SadEventKind::Dec => {
                    self.iel_resolver
                        .resolve_governance_policy_at(&branch.identity, &identity_event_said)
                        .await
                }
                SadEventKind::Icp => unreachable!("Icp handled in first-generation branch above"),
            };

            // IelDivergent: HARD pre-divergence on non-terminals; SOFT for
            // terminals OR post-divergence on the SE chain.
            let resolved_policy = match policy_resolution {
                Ok(p) => p,
                Err(KelsError::IelDivergent(_)) if auth_soft_eligible => {
                    self.policy_satisfied = false;
                    if is_terminal {
                        self.record_terminal_landing(event, &mut new_branches, branch, false);
                    } else {
                        Self::record_non_terminal_soft_landing(event, &mut new_branches, branch);
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };

            // Step 3.5 (β-ordering) — IEL satisfied-check. After resolve_*_at,
            // before the anchor check. The trait now returns
            // `IelSatisfaction` (#156); the SE walk maps each variant per
            // the documented contract:
            //   - Satisfied        → continue.
            //   - AuthFailed       → soft-eligible carve-out (terminals or
            //                        post-SE-divergence land soft); else HARD.
            //   - MissingEvent     → HARD here; Gap 3's collect-mode walk
            //                        will route this to deferrable accumulation.
            //   - PermanentFailure → HARD always (chain-integrity).
            let iel_satisfaction = self
                .iel_resolver
                .is_satisfied(&branch.identity, &identity_event_said)
                .await?;
            match iel_satisfaction {
                crate::IelSatisfaction::Satisfied => {}
                crate::IelSatisfaction::AuthFailed { reason: _ } => {
                    if auth_soft_eligible {
                        self.policy_satisfied = false;
                        if is_terminal {
                            self.record_terminal_landing(event, &mut new_branches, branch, false);
                        } else {
                            Self::record_non_terminal_soft_landing(
                                event,
                                &mut new_branches,
                                branch,
                            );
                        }
                        continue;
                    }
                    return Err(KelsError::VerificationFailed(format!(
                        "SE {} event {}: bound IEL event {} did not satisfy IEL verification \
                         (auth-fail; non-terminal pre-SE-divergence)",
                        event.kind, event.said, identity_event_said,
                    )));
                }
                crate::IelSatisfaction::MissingEvent {
                    iel_prefix,
                    event_said,
                } => {
                    // Soft-eligible takes precedence: terminals /
                    // post-SE-divergence land soft regardless of
                    // bound IEL event state.
                    if auth_soft_eligible {
                        self.policy_satisfied = false;
                        if is_terminal {
                            self.record_terminal_landing(event, &mut new_branches, branch, false);
                        } else {
                            Self::record_non_terminal_soft_landing(
                                event,
                                &mut new_branches,
                                branch,
                            );
                        }
                        continue;
                    }
                    if self.collecting {
                        self.deferred_failures
                            .push(DeferredFailure::missing_iel_event(iel_prefix, event_said));
                        self.policy_satisfied = false;
                        Self::record_non_terminal_soft_landing(event, &mut new_branches, branch);
                        continue;
                    }
                    return Err(KelsError::missing_iel_event(iel_prefix, event_said));
                }
                crate::IelSatisfaction::PermanentFailure(violation) => {
                    return Err(KelsError::IdentityBindingViolation(violation));
                }
            }

            // Step 4 — anchor check. HARD pre-divergence on non-terminals;
            // SOFT for terminals OR post-divergence. Gap 2 consumes only
            // `evaluation.satisfied` for behavior-equivalence; Gap 3's
            // collect-mode walk routes `evaluation.missing_anchors` into
            // the deferrable accumulator. Gap-8 (#156 follow-on): the
            // checker can also return `KelsError::MissingSadObject` when
            // the resolved Policy SAD itself hasn't propagated locally;
            // route that through the same soft-eligible / collect / hard
            // disposition as the in-band failures.
            let evaluation = match self.checker.evaluate(&event.said, &resolved_policy).await {
                Ok(eval) => eval,
                Err(KelsError::MissingSadObject(_)) if auth_soft_eligible => {
                    self.policy_satisfied = false;
                    if is_terminal {
                        self.record_terminal_landing(event, &mut new_branches, branch, false);
                    } else {
                        Self::record_non_terminal_soft_landing(event, &mut new_branches, branch);
                    }
                    continue;
                }
                Err(KelsError::MissingSadObject(missing)) if self.collecting => {
                    self.deferred_failures
                        .push(DeferredFailure::missing_sad_object(missing.said));
                    self.policy_satisfied = false;
                    Self::record_non_terminal_soft_landing(event, &mut new_branches, branch);
                    continue;
                }
                Err(e) => return Err(e),
            };

            if !evaluation.satisfied {
                // Soft-eligible path (terminals + post-SE-divergence)
                // takes precedence over collect-mode accumulation.
                // Terminals are intentionally soft-fail — the chain
                // still lands as terminal regardless of anchor state;
                // accumulating their anchors as deferrable would prevent
                // the expected terminal landing.
                if auth_soft_eligible {
                    self.policy_satisfied = false;
                    if is_terminal {
                        self.record_terminal_landing(event, &mut new_branches, branch, false);
                    } else {
                        Self::record_non_terminal_soft_landing(event, &mut new_branches, branch);
                    }
                    continue;
                }
                // Collect-mode (#156) for the otherwise-HARD path: if the
                // policy could be satisfied by a missing anchor's
                // commitment, accumulate each as a deferrable failure and
                // soft-fail-style continue. Empty `missing_anchors`
                // (policy permanently unsatisfiable) falls through to
                // hard-fail.
                if self.collecting && !evaluation.missing_anchors.is_empty() {
                    for kel_prefix in &evaluation.missing_anchors {
                        self.deferred_failures
                            .push(DeferredFailure::missing_kel_anchor(*kel_prefix, event.said));
                    }
                    self.policy_satisfied = false;
                    Self::record_non_terminal_soft_landing(event, &mut new_branches, branch);
                    continue;
                }
                return Err(KelsError::VerificationFailed(format!(
                    "SE {} event {} not anchored under resolved policy {} \
                     (bound IEL event {})",
                    event.kind, event.said, resolved_policy, identity_event_said,
                )));
            }

            // Step 5 — monotonic ratchet (uses positions fetched above). HARD
            // for all kinds.
            let new_position = position_batch.get(&identity_event_said).ok_or_else(|| {
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
                    let prior_position = position_batch.get(&prior_said).ok_or_else(|| {
                        KelsError::VerificationFailed(format!(
                            "Branch's prior last_identity_event {} missing from prefetched \
                             IEL positions (resolver invariant breach)",
                            prior_said,
                        ))
                    })?;
                    use std::cmp::Ordering;
                    match new_position.try_cmp(prior_position) {
                        Ok(Ordering::Less) => {
                            return Err(KelsError::identity_binding_violation(format!(
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
                            // `IdentityBindingViolation` for the
                            // chain-integrity umbrella per #156).
                            return Err(KelsError::identity_binding_violation(format!(
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
                    (
                        branch.last_governance_version,
                        branch.events_since_evaluation + 1,
                    )
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
                    (
                        branch.last_governance_version,
                        branch.events_since_evaluation,
                    )
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

            // Satisfied-SAIDs tracking. Predicate: SAID was queried, the
            // event passed every auth-related gate (IelDivergent, satisfied,
            // anchor) reaching this point, AND the event lives at
            // `version < first_divergent_version` (or chain non-divergent).
            // Cnt is structurally always at-or-after divergence — never lands
            // here. Dec on a clean chain CAN.
            if !post_divergence_soft && self.queried_saids.contains(&event.said) {
                self.satisfied_saids.insert(event.said);
            }
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
    /// IelDivergent guard, satisfied-check, or anchor check). The event
    /// lands on the chain (replaces the parent branch tip) and sets the
    /// appropriate terminal flag content-based, but does NOT advance
    /// `last_identity_event`, `last_governance_version`, or
    /// `events_since_evaluation` — per the "Update precondition" rule
    /// that keeps the ratchet pinned to a known-clean position.
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

    /// Record a SOFT-passed non-terminal event (Upd/Sea/Rpr that failed an
    /// auth-related gate post-divergence — IelDivergent, satisfied-check,
    /// or anchor-fail). The event lands as the new branch tip but preserves
    /// all other branch state (no ratchet advance, no seal advance, counter
    /// preserved). Used only on post-divergence soft conversion; pre-divergence
    /// HARD-fails for these kinds still return Err.
    fn record_non_terminal_soft_landing(
        event: &SadEvent,
        new_branches: &mut HashMap<cesr::Digest256, SadBranchTip>,
        parent: &SadBranchTip,
    ) {
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

    /// #156 collect-mode sibling of [`verify_page`]. Equivalent to
    /// enabling collecting + calling `verify_page`. Deferrable failures
    /// (`MissingIelEvent`, `MissingKelAnchor`) accumulate into the
    /// verifier's internal buffer (read via [`deferred_failures`]) and
    /// the walk soft-fails the affected events; permanent failures still
    /// halt with `Err(KelsError)`.
    pub async fn verify_page_collecting(&mut self, events: &[SadEvent]) -> Result<(), KelsError> {
        self.collecting = true;
        self.verify_page(events).await
    }

    /// #156 collect-mode sibling of [`finish`]. Returns the verification
    /// token alongside the accumulated deferrable failures. Caller maps
    /// non-empty `Vec<DeferredFailure>` to a 422 + dep info wire response;
    /// empty means the chain verified cleanly.
    pub async fn finish_collecting(
        mut self,
    ) -> Result<(SelVerification, Vec<DeferredFailure>), KelsError> {
        self.collecting = true;
        self.finish_internal().await
    }

    /// Shared finalization. `finish` discards the deferred-failures vec;
    /// `finish_collecting` returns it alongside the verification token.
    /// Flushing the buffered generation is the side that may push new
    /// entries into `deferred_failures` (when `collecting=true`), so the
    /// take-after-flush ordering matters.
    async fn finish_internal(
        mut self,
    ) -> Result<(SelVerification, Vec<DeferredFailure>), KelsError> {
        self.flush_generation().await?;
        let deferred = std::mem::take(&mut self.deferred_failures);

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

        // #147 / #171 inception batch rule: a chain whose tip is still the
        // Icp never received its paired v1 Upd. Icp is structurally pinned
        // to v=0 (rejected at any other version in `flush_generation`), so
        // an Icp tip is sufficient to identify the lone-`[Icp]` chain.
        // This is a chain-validity rule — every consumer's verifier walk
        // rejects the same shape.
        if self
            .branches
            .values()
            .any(|b| b.tip.kind == SadEventKind::Icp)
        {
            return Err(KelsError::IncompleteInception(
                "chain ends at Icp without an Upd at v1".into(),
            ));
        }

        let mut branches: Vec<SadBranchTip> = self.branches.into_values().collect();
        branches.sort_by_key(|b| b.tip.said);

        let last_governance_version = branches
            .iter()
            .filter_map(|b| b.last_governance_version)
            .max();

        Ok((
            SelVerification::new(
                branches,
                self.policy_satisfied,
                self.is_contested,
                self.is_decommissioned,
                last_governance_version,
                self.diverged_at_version,
                self.queried_saids,
                self.satisfied_saids,
            ),
            deferred,
        ))
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

    /// Finish verification and produce the proof token. Strict-mode
    /// callers ignore any deferrable accumulator (they shouldn't have
    /// any, since strict-mode halts on the first deferrable).
    pub async fn finish(self) -> Result<SelVerification, KelsError> {
        let (verification, _deferred) = self.finish_internal().await?;
        Ok(verification)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use crate::types::{
        AnchorEvaluation, IdentityEvent, IdentityEventKind, IelChainPosition,
        IelChainPositionBatch, IelSatisfaction,
    };

    const TEST_TOPIC: &str = "kels/sad/v1/keys/mlkem";

    fn d(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    // ==================== Test fakes ====================

    /// `PolicyChecker` that always returns satisfied.
    struct AlwaysPassChecker;
    #[async_trait::async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn evaluate(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<AnchorEvaluation, KelsError> {
            Ok(AnchorEvaluation {
                satisfied: true,
                missing_anchors: Vec::new(),
            })
        }
        async fn is_immune(&self, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    /// `PolicyChecker` that returns `satisfied=false` for SAIDs in a
    /// reject-list, satisfied otherwise. Used to drive soft/hard fail cases
    /// per kind.
    struct RejectingChecker {
        reject: HashSet<cesr::Digest256>,
    }
    #[async_trait::async_trait]
    impl PolicyChecker for RejectingChecker {
        async fn evaluate(
            &self,
            said: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<AnchorEvaluation, KelsError> {
            Ok(AnchorEvaluation {
                satisfied: !self.reject.contains(said),
                missing_anchors: Vec::new(),
            })
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
                return Err(KelsError::identity_binding_violation(format!(
                    "FakeIelResolver: identity mismatch (got {}, expected {})",
                    identity, self.identity
                )));
            }
            let entry = self
                .events
                .get(said)
                .ok_or_else(|| KelsError::missing_iel_event(*identity, *said))?;
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

        async fn is_satisfied(
            &self,
            identity: &cesr::Digest256,
            said: &cesr::Digest256,
        ) -> Result<IelSatisfaction, KelsError> {
            // Test fake: re-classify fetch errors into the new
            // `IelSatisfaction` variants per #156. For the satisfied
            // predicate, mirror the production rule: pre-divergence (or
            // chain non-divergent) → Satisfied; post-divergence → AuthFailed
            // (analog of "in-chain but soft-failed"). The fake's `events`
            // map doesn't record auth-pass-status, so otherwise default to
            // "auth-passed" — tests that need to pin auth-fail-soft cases
            // construct chains where the SE checker rejects, exercising the
            // SE-side gate without driving an in-fake IEL verifier.
            let event = match self.fetch_iel_event(identity, said).await {
                Ok(e) => e,
                Err(KelsError::MissingIelEvent(dep)) => {
                    return Ok(IelSatisfaction::MissingEvent {
                        iel_prefix: dep.iel_prefix,
                        event_said: dep.event_said,
                    });
                }
                Err(KelsError::IdentityBindingViolation(violation)) => {
                    return Ok(IelSatisfaction::PermanentFailure(violation));
                }
                Err(other) => return Err(other),
            };
            let post_divergence = self
                .first_divergent_version
                .is_some_and(|d| event.version >= d);
            if post_divergence {
                Ok(IelSatisfaction::AuthFailed {
                    reason: format!(
                        "FakeIelResolver: event {} at version {} is post-divergence",
                        said, event.version,
                    ),
                })
            } else {
                Ok(IelSatisfaction::Satisfied)
            }
        }

        async fn iel_chain_positions(
            &self,
            identity: &cesr::Digest256,
            saids: &[cesr::Digest256],
        ) -> Result<IelChainPositionBatch, KelsError> {
            if identity != &self.identity {
                return Err(KelsError::identity_binding_violation(format!(
                    "FakeIelResolver: identity mismatch (got {}, expected {})",
                    identity, self.identity
                )));
            }
            let mut found: Vec<IelChainPosition> = Vec::new();
            let mut missing: Vec<cesr::Digest256> = Vec::new();
            for said in saids {
                let Some(entry) = self.events.get(said) else {
                    missing.push(*said);
                    continue;
                };
                let branch_marker = match self.first_divergent_version {
                    Some(d) if entry.version >= d => Some(*said),
                    _ => None,
                };
                found.push(IelChainPosition {
                    version: entry.version,
                    kind: entry.kind,
                    said: *said,
                    branch_marker,
                });
            }
            Ok(IelChainPositionBatch { found, missing })
        }

        async fn resolve_identity_for_event(
            &self,
            said: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            if self.events.contains_key(said) {
                Ok(self.identity)
            } else {
                // SAID-only fetch — no `iel_prefix` to populate
                // `MissingIelEvent`; return permanent. Mirrors the
                // production resolvers' classification at this site.
                Err(KelsError::identity_binding_violation(format!(
                    "FakeIelResolver: no event for SAID {}",
                    said
                )))
            }
        }

        async fn resolve_current_auth_policy(
            &self,
            identity: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            if identity != &self.identity {
                return Err(KelsError::identity_binding_violation(format!(
                    "FakeIelResolver: identity mismatch (got {}, expected {})",
                    identity, self.identity
                )));
            }
            // Test fake: pick the highest-version event's auth_policy as the
            // "current" view. Tests that need terminal/divergent semantics
            // can set `first_divergent_version` and assert IelDivergent
            // separately; this stub just feeds back the most recently
            // declared auth_policy.
            if let Some(divergent) = self.first_divergent_version {
                return Err(KelsError::IelDivergent(format!(
                    "FakeIelResolver: IEL is divergent at {}",
                    divergent
                )));
            }
            self.events
                .values()
                .max_by_key(|e| e.version)
                .map(|e| e.auth_policy)
                .ok_or_else(|| {
                    KelsError::NotFound(format!("FakeIelResolver: IEL {} has no events", identity,))
                })
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
        SadEvent::icp(identity, TEST_TOPIC).unwrap()
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

    /// #171: a chain whose only event is `Icp` (branch tip is still Icp at v0)
    /// is rejected with `IncompleteInception`. The rule lives in the verifier
    /// so every consumer's walk applies it — a tampered DB serving lone `[Icp]`
    /// fails end-verification.
    #[tokio::test]
    async fn lone_icp_rejected_with_incomplete_inception() {
        let identity = d(b"identity-lone-icp");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[],
            d(b"auth-lone"),
            d(b"gov-lone"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0]).await.unwrap();
        let err = verifier.finish().await.expect_err("lone Icp must reject");
        assert!(
            matches!(err, KelsError::IncompleteInception(_)),
            "expected IncompleteInception, got {:?}",
            err
        );
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

    /// #156 collect-mode: a batch with a single `Upd` referencing an
    /// unknown IEL event accumulates one `DeferredFailure::MissingIelEvent`
    /// instead of halting with `Err`. `finish_collecting` returns the
    /// verification token alongside the collected failures; the chain
    /// soft-failed at the missing-event gate, so `policy_satisfied=false`.
    #[tokio::test]
    async fn collect_mode_accumulates_missing_iel_event() {
        let identity = d(b"identity-collect-mie");
        let iel_icp = d(b"iel-icp-collect-mie");
        let unknown = d(b"unknown-iel-event-collect");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-collect-mie"),
            d(b"gov-collect-mie"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, unknown, b"c1");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier
            .verify_page_collecting(&[v0, v1])
            .await
            .expect("collect-mode does not halt on missing IEL event");
        let (verification, deferred) = verifier
            .finish_collecting()
            .await
            .expect("finish_collecting returns token");

        // The walk may emit the same `MissingIelEvent` from multiple
        // gates (the bulk `iel_chain_positions` partial-results check and
        // the per-event `fetch_iel_event` Step 1). The wire-format layer
        // dedupes via `BTreeSet<DepRef>`; the verifier-level accumulator
        // doesn't, so just assert at least one matching entry exists.
        assert!(deferred.iter().any(|d| matches!(
            d,
            DeferredFailure::MissingIelEvent(dep)
                if dep.iel_prefix == identity && dep.event_said == unknown
        )));
        // Soft-fail-style state advancement: chain landed but policy not satisfied.
        assert!(!verification.policy_satisfied());
    }

    /// #156 collect-mode: permanent failures (here: monotonic-ratchet
    /// regression / chain-integrity breach) still halt the walk with
    /// `Err(KelsError)`; the deferred accumulator is discarded.
    #[tokio::test]
    async fn collect_mode_permanent_failure_still_halts() {
        let identity = d(b"identity-collect-perm");
        let iel_icp = d(b"iel-icp-collect-perm");
        let iel_evl = d(b"iel-evl-collect-perm");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[
                (iel_icp, 0, IdentityEventKind::Icp),
                (iel_evl, 1, IdentityEventKind::Evl),
            ],
            d(b"auth-collect-perm"),
            d(b"gov-collect-perm"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        // v1 binds to the later IEL Evl, ratcheting the branch forward.
        let v1 = make_upd(&v0, iel_evl, b"c1");
        // v2 binds to the earlier IEL Icp, regressing the ratchet → permanent.
        let v2 = make_upd(&v1, iel_icp, b"c2");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier
            .verify_page_collecting(&[v0, v1, v2])
            .await
            .unwrap();
        let err = verifier
            .finish_collecting()
            .await
            .expect_err("permanent failure halts collect-mode");
        assert!(matches!(err, KelsError::IdentityBindingViolation(_)));
    }

    /// #156 collect-mode: anchor evaluation that reports a non-empty
    /// `missing_anchors` list (deferrable: KEL endorsers haven't anchored
    /// yet) accumulates one `DeferredFailure::MissingKelAnchor` per
    /// missing endorser. The walk soft-fails the affected event.
    #[tokio::test]
    async fn collect_mode_accumulates_missing_kel_anchor() {
        // Custom checker returning a specific missing-anchor for any
        // (said, policy) lookup.
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

        let identity = d(b"identity-collect-mka");
        let iel_icp = d(b"iel-icp-collect-mka");
        let kel_prefix = d(b"missing-kel-prefix");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-collect-mka"),
            d(b"gov-collect-mka"),
        )) as Arc<dyn IelResolver + Send + Sync>;
        let checker: Arc<dyn PolicyChecker + Send + Sync> =
            Arc::new(MissingAnchorChecker { kel_prefix });

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1-mka");
        let v1_said = v1.said;

        let mut verifier = SelVerifier::new(Some(&v0.prefix), checker, resolver);
        verifier
            .verify_page_collecting(&[v0, v1])
            .await
            .expect("collect-mode does not halt on missing anchor");
        let (verification, deferred) = verifier.finish_collecting().await.unwrap();

        assert_eq!(deferred.len(), 1);
        assert!(matches!(
            &deferred[0],
            DeferredFailure::MissingKelAnchor(dep)
                if dep.kel_prefix == kel_prefix && dep.anchor_said == v1_said
        ));
        assert!(!verification.policy_satisfied());
    }

    /// Collect-mode (#156 Gap-8): when the `PolicyChecker.evaluate` call
    /// returns `KelsError::MissingSadObject` (the resolved Policy SAD
    /// hasn't propagated locally), the SEL verifier accumulates a
    /// `DeferredFailure::MissingSadObject` and continues the walk
    /// soft-fail-style. Strict mode would halt; collect mode lets the
    /// handler emit a typed-422 with `sad_object` deps so gossip can
    /// park on `pending:said:{policy_said}` and drain when the SAD
    /// object commits.
    #[tokio::test]
    async fn collect_mode_accumulates_missing_sad_object() {
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

        let identity = d(b"identity-collect-msa");
        let iel_icp = d(b"iel-icp-collect-msa");
        let auth = d(b"auth-collect-msa");
        let gov = d(b"gov-collect-msa");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            auth,
            gov,
        )) as Arc<dyn IelResolver + Send + Sync>;
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(MissingSadObjectChecker);

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1-msa");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), checker, resolver);
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
    /// SEL checker propagates through `verify_page` / `finish` as Err.
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

        let identity = d(b"identity-strict-msa");
        let iel_icp = d(b"iel-icp-strict-msa");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-strict-msa"),
            d(b"gov-strict-msa"),
        )) as Arc<dyn IelResolver + Send + Sync>;
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(MissingSadObjectChecker);

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1-strict-msa");

        let mut verifier = SelVerifier::new(Some(&v0.prefix), checker, resolver);
        verifier.verify_page(&[v0, v1]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            matches!(err, KelsError::MissingSadObject(_)),
            "expected MissingSadObject, got {err:?}"
        );
    }

    /// `event.identity_event` referencing an unknown SAID → `MissingIelEvent`
    /// (deferrable, post-#156 split) from the resolver.
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
            matches!(err, KelsError::MissingIelEvent(_)),
            "expected MissingIelEvent, got {err:?}"
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
            matches!(err, KelsError::IdentityBindingViolation(_))
                && err.to_string().contains("regresses prior ratchet"),
            "expected IdentityBindingViolation(monotonic), got {err:?}"
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

    /// #171 terminal-state gate: a non-terminal event (`Upd`) extending a
    /// `Cnt` tip is structurally invalid. Tampered chain shape that the
    /// verifier rejects on read so consumers can't be tricked into honoring
    /// post-terminal extensions.
    #[tokio::test]
    async fn upd_extending_cnt_tip_rejected_as_post_terminal() {
        let identity = d(b"identity-post-cnt");
        let iel_icp = d(b"iel-icp-post-cnt");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-post-cnt"),
            d(b"gov-post-cnt"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let cnt = SadEvent::cnt(&v1, iel_icp).unwrap();
        let post = SadEvent::upd(&cnt, iel_icp, d(b"post-terminal")).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, cnt, post]).await.unwrap();
        let err = verifier
            .finish()
            .await
            .expect_err("post-terminal extension must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("cannot extend terminal"),
            "expected Cnt-tombstone rejection, got {msg}"
        );
    }

    /// #171 SE divergent-chain gate (unsealed-divergent): on an
    /// unsealed-divergent chain (no Sea/Rpr advanced past divergence),
    /// only `Rpr` is allowed post-divergence — `Rpr` truncates the
    /// adversary branch and resolves cleanly. The legitimate-resolver
    /// rule.
    #[tokio::test]
    async fn rpr_on_unsealed_divergent_accepted() {
        let identity = d(b"identity-rpr-unsealed");
        let iel_icp = d(b"iel-icp-rpr-unsealed");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-rpr-unsealed"),
            d(b"gov-rpr-unsealed"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let v2_a = make_upd_with_content(&v1, iel_icp, b"branch-a");
        let v2_b = make_upd_with_content(&v1, iel_icp, b"branch-b");
        let (lo, hi) = if v2_a.said.as_ref() < v2_b.said.as_ref() {
            (v2_a, v2_b)
        } else {
            (v2_b, v2_a)
        };
        let rpr = SadEvent::rpr(&lo, iel_icp).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, lo, hi, rpr]).await.unwrap();
        let v = verifier.finish().await.unwrap();
        assert_eq!(v.diverged_at_version(), Some(2));
        assert!(v.policy_satisfied());
    }

    /// #171 SE divergent-chain gate (sealed-divergent rejects Rpr): once
    /// the seal has advanced to-or-past the divergence point, `Rpr`
    /// cannot truncate behind the seal — only `Cnt` is the legitimate
    /// move.
    #[tokio::test]
    async fn rpr_on_sealed_divergent_rejected() {
        let identity = d(b"identity-rpr-sealed");
        let iel_icp = d(b"iel-icp-rpr-sealed");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-rpr-sealed"),
            d(b"gov-rpr-sealed"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        // Sealed-divergent shape: Sea-creates-divergence at v=2 (Sea and
        // Upd both extending v=1, both at v=2). Sea's branch advances
        // last_gov to 2; div_at=2, max_seal=2 → sealed-divergent.
        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let upd_v2 = make_upd_with_content(&v1, iel_icp, b"upd-fork");
        let sea_v2 = SadEvent::sea(&v1, iel_icp).unwrap();
        let rpr = SadEvent::rpr(&upd_v2, iel_icp).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier
            .verify_page(&[v0, v1, upd_v2, sea_v2, rpr])
            .await
            .unwrap();
        let err = verifier
            .finish()
            .await
            .expect_err("Rpr on sealed-divergent must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("sealed-divergent") && msg.contains("only Cnt"),
            "expected sealed-divergent rejection, got {msg}"
        );
    }

    /// #171 SE divergent-chain gate (sealed-divergent accepts Cnt): the
    /// only legitimate resolver on a sealed-divergent chain.
    #[tokio::test]
    async fn cnt_on_sealed_divergent_accepted() {
        let identity = d(b"identity-cnt-sealed");
        let iel_icp = d(b"iel-icp-cnt-sealed");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-cnt-sealed"),
            d(b"gov-cnt-sealed"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let upd_v2 = make_upd_with_content(&v1, iel_icp, b"upd-fork");
        let sea_v2 = SadEvent::sea(&v1, iel_icp).unwrap();
        let cnt = SadEvent::cnt(&upd_v2, iel_icp).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier
            .verify_page(&[v0, v1, upd_v2, sea_v2, cnt])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();
        assert_eq!(v.diverged_at_version(), Some(2));
        assert!(v.is_contested());
    }

    /// #171 SE divergent-chain gate (unsealed-divergent rejects Cnt):
    /// `Cnt` is reserved for sealed-divergent — on unsealed-divergent
    /// the operator must `Rpr` instead.
    #[tokio::test]
    async fn cnt_on_unsealed_divergent_rejected() {
        let identity = d(b"identity-cnt-unsealed");
        let iel_icp = d(b"iel-icp-cnt-unsealed");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-cnt-unsealed"),
            d(b"gov-cnt-unsealed"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let v2_a = make_upd_with_content(&v1, iel_icp, b"branch-a");
        let v2_b = make_upd_with_content(&v1, iel_icp, b"branch-b");
        let (lo, _hi) = if v2_a.said.as_ref() < v2_b.said.as_ref() {
            (v2_a.clone(), v2_b.clone())
        } else {
            (v2_b.clone(), v2_a.clone())
        };
        let cnt = SadEvent::cnt(&lo, iel_icp).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier
            .verify_page(&[v0, v1, v2_a, v2_b, cnt])
            .await
            .unwrap();
        let err = verifier
            .finish()
            .await
            .expect_err("Cnt on unsealed-divergent must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("unsealed-divergent") && msg.contains("only Rpr"),
            "expected unsealed-divergent rejection, got {msg}"
        );
    }

    /// #171 terminal-state gate: same shape for `Dec` — a non-terminal event
    /// extending a `Dec` tip is structurally invalid.
    #[tokio::test]
    async fn upd_extending_dec_tip_rejected_as_post_terminal() {
        let identity = d(b"identity-post-dec");
        let iel_icp = d(b"iel-icp-post-dec");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-post-dec"),
            d(b"gov-post-dec"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let dec = SadEvent::dec(&v1, iel_icp).unwrap();
        let post = SadEvent::upd(&dec, iel_icp, d(b"post-terminal")).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, dec, post]).await.unwrap();
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
        let identity = d(b"identity-cnt-extends-dec");
        let iel_icp = d(b"iel-icp-cnt-extends-dec");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-cnt-extends-dec"),
            d(b"gov-cnt-extends-dec"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let dec = SadEvent::dec(&v1, iel_icp).unwrap();
        let cnt = SadEvent::cnt(&dec, iel_icp).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, dec, cnt]).await.unwrap();
        let err = verifier
            .finish()
            .await
            .expect_err("Cnt extending Dec tip must reject (Cnt-supersedes-Dec deferred to #174)");
        assert!(err.to_string().contains("cannot extend terminal"));
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

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), Arc::clone(&resolver));
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
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

    // ==================== Caller-bounded SAID querying ====================

    /// Pre-divergence SE events that pass auth land in `satisfied_saids`
    /// when the caller registered them via `check_satisfied`.
    #[tokio::test]
    async fn satisfied_saids_populates_for_pre_divergence_se_events() {
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
        verifier.check_satisfied([v0.said, v1.said]);
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.is_said_satisfied(&v0.said));
        assert!(v.is_said_satisfied(&v1.said));
    }

    /// SAIDs not registered are absent from `satisfied_saids`, even if
    /// the events themselves landed and passed auth.
    #[tokio::test]
    async fn satisfied_saids_excludes_unqueried_se_events() {
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

        // Only v1 registered; v0 isn't.
        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.check_satisfied([v1.said]);
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(!v.is_said_satisfied(&v0.said));
        assert!(v.is_said_satisfied(&v1.said));
    }

    /// Resume rehydrates `queried_saids` and `satisfied_saids` from the
    /// prior token. Diverges from KEL's reset-on-resume; the IEL/SE
    /// streaming pre-walk pattern needs registered interest to persist.
    #[tokio::test]
    async fn resume_rehydrates_queried_and_satisfied_saids_se() {
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

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), Arc::clone(&resolver));
        verifier.check_satisfied([v0.said, v1.said]);
        verifier
            .verify_page(&[v0.clone(), v1.clone()])
            .await
            .unwrap();
        let token = verifier.finish().await.unwrap();
        assert!(token.is_said_satisfied(&v0.said));
        assert!(token.is_said_satisfied(&v1.said));

        // Resume preserves the registered set + accumulated satisfied set.
        let v2 = make_upd(&v1, iel_icp, b"content-2");
        let mut resumed =
            SelVerifier::resume(&token, always_pass(), Arc::clone(&resolver)).unwrap();
        resumed
            .verify_page(std::slice::from_ref(&v2))
            .await
            .unwrap();
        let extended = resumed.finish().await.unwrap();

        assert!(extended.is_said_satisfied(&v0.said));
        assert!(extended.is_said_satisfied(&v1.said));
    }

    // ==================== Post-divergence soft-fail propagation ====================

    /// Building helper: produce an Upd extending `prev` with a fixed
    /// `iel_event` binding and content. Mirrors `make_upd` shape.
    fn make_upd_with_content(
        prev: &SadEvent,
        iel_evt: cesr::Digest256,
        content_label: &[u8],
    ) -> SadEvent {
        SadEvent::upd(prev, iel_evt, d(content_label)).unwrap()
    }

    // ==================== #147 follow-up: missing taxonomy ====================

    /// Sea binding to a divergent-IEL post-divergence event: HARD reject
    /// (advancement event; chain does not advance). Parallel of
    /// `upd_binding_to_divergent_iel_event_hard_rejects`.
    #[tokio::test]
    async fn sea_binding_to_divergent_iel_event_hard_rejects() {
        let identity = d(b"identity-sea-div");
        let iel_icp = d(b"iel-icp-sea-div");
        let iel_evl_div = d(b"iel-evl-sea-div");

        let resolver = Arc::new(
            FakeIelResolver::new(identity)
                .with_event(
                    iel_icp,
                    0,
                    IdentityEventKind::Icp,
                    d(b"auth-sea-div"),
                    d(b"gov-sea-div"),
                )
                .with_event(
                    iel_evl_div,
                    1,
                    IdentityEventKind::Evl,
                    d(b"auth-sea-div"),
                    d(b"gov-sea-div"),
                )
                .with_divergence_at(1),
        ) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        // Sea binds to the post-divergence IEL Evl. HARD reject: SE chain
        // is non-divergent (Sea is the first thing past v=1 that would
        // touch the divergent IEL), so the auth-fail isn't soft-converted.
        let sea = SadEvent::sea(&v1, iel_evl_div).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, sea]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            matches!(err, KelsError::IelDivergent(_)),
            "expected IelDivergent, got {err:?}"
        );
    }

    /// Rpr binding to a divergent-IEL post-divergence event: HARD reject.
    #[tokio::test]
    async fn rpr_binding_to_divergent_iel_event_hard_rejects() {
        let identity = d(b"identity-rpr-div");
        let iel_icp = d(b"iel-icp-rpr-div");
        let iel_evl_div = d(b"iel-evl-rpr-div");

        let resolver = Arc::new(
            FakeIelResolver::new(identity)
                .with_event(
                    iel_icp,
                    0,
                    IdentityEventKind::Icp,
                    d(b"auth-rpr-div"),
                    d(b"gov-rpr-div"),
                )
                .with_event(
                    iel_evl_div,
                    1,
                    IdentityEventKind::Evl,
                    d(b"auth-rpr-div"),
                    d(b"gov-rpr-div"),
                )
                .with_divergence_at(1),
        ) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        // Rpr binds to the post-divergence IEL Evl. Same HARD path as Sea
        // — Rpr is an advancement event (resolves divergence on SE side)
        // and cannot rest on an unstable IEL state.
        let rpr = SadEvent::rpr(&v1, iel_evl_div).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, rpr]).await.unwrap();
        let err = verifier.finish().await.unwrap_err();
        assert!(
            matches!(err, KelsError::IelDivergent(_)),
            "expected IelDivergent, got {err:?}"
        );
    }

    /// Dec binding to a divergent-IEL post-divergence event: SOFT-passes
    /// (lands; chain becomes decommissioned content-based;
    /// `policy_satisfied=false`). Parallel of
    /// `cnt_with_divergent_iel_binding_lands_softly`.
    #[tokio::test]
    async fn dec_with_divergent_iel_binding_lands_softly() {
        let identity = d(b"identity-dec-div");
        let iel_icp = d(b"iel-icp-dec-div");
        let iel_evl_div = d(b"iel-evl-dec-div");

        let resolver = Arc::new(
            FakeIelResolver::new(identity)
                .with_event(
                    iel_icp,
                    0,
                    IdentityEventKind::Icp,
                    d(b"auth-dec-div"),
                    d(b"gov-dec-div"),
                )
                .with_event(
                    iel_evl_div,
                    1,
                    IdentityEventKind::Evl,
                    d(b"auth-dec-div"),
                    d(b"gov-dec-div"),
                )
                .with_divergence_at(1),
        ) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        let v1 = make_upd(&v0, iel_icp, b"c1");
        let dec = SadEvent::dec(&v1, iel_evl_div).unwrap();

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier.verify_page(&[v0, v1, dec]).await.unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.is_decommissioned());
        assert!(!v.is_contested());
        assert!(!v.policy_satisfied());
        // Ratchet pinned to the hard-passed v1 binding; soft-passed Dec
        // does NOT advance it.
        assert_eq!(v.branches()[0].last_identity_event, Some(iel_icp));
    }

    /// `[Icp, Sea]` content preservation when no Upd has landed: previous
    /// content is `None`, Sea must preserve `None`. Pins the
    /// content-preservation rule on the no-Upd branch.
    #[tokio::test]
    async fn sea_after_icp_no_upd_preserves_none_content() {
        let identity = d(b"identity-sea-noupd");
        let iel_icp = d(b"iel-icp-sea-noupd");

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-sea-noupd"),
            d(b"gov-sea-noupd"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let v0 = make_icp(identity);
        // Sea directly after Icp — no Upd in between. v0.content is None
        // (Icp forbids content), and Sea must carry that forward.
        let sea = SadEvent::sea(&v0, iel_icp).unwrap();
        assert!(
            sea.content.is_none(),
            "constructor must seed Sea.content from previous (None for Icp)"
        );

        let mut verifier = SelVerifier::new(Some(&v0.prefix), always_pass(), resolver);
        verifier
            .verify_page(&[v0.clone(), sea.clone()])
            .await
            .unwrap();
        let v = verifier.finish().await.unwrap();

        assert!(v.policy_satisfied());
        assert_eq!(v.last_governance_version(), Some(1));
        assert_eq!(v.current_event().said, sea.said);
        assert!(v.current_content().is_none());
    }

    // ==================== Post-SE-divergence taxonomy ====================
    //
    // The post-divergence soft-fail rule (#147 follow-up)
    // converts auth-related failures (IelDivergent / is_satisfied=false /
    // is_anchored=false) on post-SE-divergence non-terminals from HARD to
    // SOFT. Structural integrity rules stay HARD regardless.
    //
    // Fixture pattern: divergent SE chain at v=1 via two competing Upds (Cnt
    // would also create divergence; Upd-divergence is simpler to construct
    // here and exercises the same `event.version >= diverged_at_version`
    // predicate). Post-divergence event at v=2 extends one branch.

    /// Helper: build a divergent-at-v=1 SE chain. Returns (v0, lo_v1_branch_tip,
    /// hi_v1_branch_tip, iel_icp_said).
    fn divergent_chain_at_v1() -> (
        SadEvent,
        SadEvent,
        SadEvent,
        cesr::Digest256,
        cesr::Digest256,
    ) {
        let identity = d(b"identity-postdiv");
        let iel_icp = d(b"iel-icp-postdiv");
        let v0 = make_icp(identity);
        let v1_a = make_upd_with_content(&v0, iel_icp, b"branch-a");
        let v1_b = make_upd_with_content(&v0, iel_icp, b"branch-b");
        let (lo, hi) = if v1_a.said.as_ref() < v1_b.said.as_ref() {
            (v1_a, v1_b)
        } else {
            (v1_b, v1_a)
        };
        (v0, lo, hi, identity, iel_icp)
    }

    /// Rpr post-SE-divergence with anchor-fail soft-lands.
    #[tokio::test]
    async fn rpr_post_divergence_anchor_fail_soft_lands_no_err() {
        let (v0, lo, hi, identity, iel_icp) = divergent_chain_at_v1();

        let resolver = Arc::new(fake_resolver_for_chain(
            identity,
            &[(iel_icp, 0, IdentityEventKind::Icp)],
            d(b"auth-postdiv"),
            d(b"gov-postdiv"),
        )) as Arc<dyn IelResolver + Send + Sync>;

        let rpr = SadEvent::rpr(&lo, iel_icp).unwrap();
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(RejectingChecker {
            reject: HashSet::from([rpr.said]),
        });

        let mut verifier = SelVerifier::new(Some(&v0.prefix), checker, resolver);
        verifier
            .verify_page(&[v0, lo, hi, rpr.clone()])
            .await
            .expect("post-SE-div Rpr anchor-fail should soft-pass");
        let v = verifier.finish().await.unwrap();
        assert_eq!(v.diverged_at_version(), Some(1));
        assert!(!v.policy_satisfied());
    }
}
