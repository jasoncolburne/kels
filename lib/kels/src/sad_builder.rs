//! SAD Event Log builder.
//!
//! Single-actor, protocol-agnostic construction surface for SAD Event Logs.
//! Mirrors `KeyEventBuilder` (`lib/kels/src/builder.rs`) for SELs: manages
//! chain state, enforces per-kind field rules, and flushes pending events
//! to SADStore. Does **not** anchor — anchoring is the caller's job so that
//! multi-KEL fan-out coordination (tracked as #146) can live above the
//! builder without any single-KEL assumptions baked in.
//!
//! Staging methods are synchronous (in-memory construction + validation).
//! Only `flush()` and `publish_pending()` hit the network.

use std::{collections::HashMap, sync::Arc};

use cesr::Matter;

use crate::{
    KelsError, MAX_NON_EVALUATION_EVENTS,
    client::SadStoreClient,
    store::SadStore,
    types::{PagedSadSource, PolicyChecker, SadEvent, SadEventKind, SelVerification, SelVerifier},
};

/// Outcome of a successful `SadEventBuilder::flush` — carries forward signals
/// from the server response that the local verifier could not have observed.
///
/// Forward-extensible: future flush signals (e.g., per-event acceptance
/// breakdown, server-side rate-limit headroom) get added as additional fields
/// without rebreaking the call sites.
#[derive(Debug, Clone)]
#[must_use = "FlushOutcome carries divergence signals — check diverged_at_at_submit before continuing to stage events, and check applied to distinguish committed-new from already-present-on-server"]
pub struct FlushOutcome {
    /// Server-reported divergence version, if a fork was created or
    /// already-existed at submit time. `None` means the chain is linear
    /// according to the server. The same value is also stamped onto
    /// `sad_verification().diverged_at_version()` so subsequent stagers can
    /// gate on builder state alone.
    pub diverged_at_at_submit: Option<u64>,
    /// Whether this submit committed any new events server-side. `false`
    /// means every submitted event was already present (typically a retry
    /// after a previous flush succeeded server-side but the client failed in
    /// phase 2 or 3) — the chain state is unchanged by this call. `true`
    /// means at least one event was newly accepted.
    pub applied: bool,
}

/// Builder for SAD Event Logs.
///
/// Dual-state per `KeyEventBuilder`: `sad_verification` holds the verified tail
/// (from server or store), `pending_events` holds locally staged events.
/// Accessors prefer the pending tail and fall back to verified state.
///
/// The builder is non-generic over `KeyProvider` — SAD events carry no
/// signatures; authorization is via KEL anchoring which the caller performs
/// between stage and flush.
pub struct SadEventBuilder {
    sad_client: Option<SadStoreClient>,
    sad_store: Option<Arc<dyn SadStore>>,
    /// Policy checker used for hydration in `with_prefix` and for absorbing
    /// pending events in `flush`. `None` permits offline construction (tests,
    /// staging-only flows); `flush` errors when pending is non-empty and this
    /// is unset.
    checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
    sad_verification: Option<SelVerification>,
    pending_events: Vec<SadEvent>,
    /// Prefix the caller expects this builder to operate on, captured via
    /// `with_prefix`. Carried into the `SelVerifier` at `absorb_pending`
    /// time so a later `incept`/`incept_deterministic` producing a different
    /// prefix surfaces as a structural mismatch at `flush` rather than silently
    /// creating a chain at an unexpected location.
    requested_prefix: Option<cesr::Digest256>,
}

/// Walk back from `start` via `previous` SAIDs through a SAID-keyed in-memory
/// `chain` map (typically the verified server-fetched tail), probing
/// `sad_store` at each step; the first hit (an event the owner authored and
/// stored locally) is the boundary. Used by `SadEventBuilder::repair` to find
/// the truncation boundary when the server's chain extends past owner's tip.
///
/// **Owner-local trust split.** The caller must verify `chain`'s contents
/// via `SelVerifier::verify_page` BEFORE calling this — `verify_event` runs
/// `event.verify_said()` per event, catching content forgery. With the chain
/// pre-verified, the in-memory `previous`-link traversal is sound. **The
/// boundary decision still lives in `sad_store`**: an event becomes the
/// boundary iff it's owner-authored (in the local store), regardless of
/// whether the server claims the same event.
///
/// `start` is typically the server's tip (from the verified chain map). The
/// walk first probes `start.previous`, not `start.said` — the boundary lies
/// strictly below `start` in the chain.
///
/// Mirrors `KeyEventBuilder::find_missing_owner_events` (`lib/kels/src/builder.rs`)
/// — same shape, mirrored data sources (KEL loads tail from local, probes
/// server in-memory; SEL holds verified server tail in-memory, probes local).
///
/// Bounded by `MINIMUM_PAGE_SIZE = 64` (one start + up to 63 predecessors).
/// A bound violation indicates the local cache is inconsistent with the
/// verified server view — surface as `InvalidKel`.
async fn walk_back_to_first_owner(
    sad_store: &Arc<dyn SadStore>,
    chain: &HashMap<cesr::Digest256, SadEvent>,
    start: &SadEvent,
) -> Result<SadEvent, KelsError> {
    let mut current = start.clone();
    for _ in 0..crate::MINIMUM_PAGE_SIZE {
        let prev_said = current.previous.ok_or_else(|| {
            KelsError::InvalidKel(
                "walk-back hit event with no previous before finding owner boundary".into(),
            )
        })?;
        if let Some(value) = sad_store.load(&prev_said).await? {
            return Ok(serde_json::from_value(value)?);
        }
        let next = chain.get(&prev_said).cloned().ok_or_else(|| {
            KelsError::InvalidKel(format!(
                "Cannot find owner boundary: event {} not in local store and not in \
                 verified server-fetched chain — local cache may be inconsistent",
                prev_said
            ))
        })?;
        current = next;
    }
    Err(KelsError::InvalidKel(
        "repair walk-back exceeded governance bound — local cache may be inconsistent with server view"
            .into(),
    ))
}

impl SadEventBuilder {
    // ==================== Constructors ====================

    /// Construct a bare builder. All three deps are optional: `sad_client` and
    /// `sad_store` may be `None` for offline construction (tests, staging-only
    /// flows). `checker` may be `None` if the builder will only stage events;
    /// `flush()` requires both `sad_client` and `checker` to be `Some`.
    pub fn new(
        sad_client: Option<SadStoreClient>,
        sad_store: Option<Arc<dyn SadStore>>,
        checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
    ) -> Self {
        Self {
            sad_client,
            sad_store,
            checker,
            sad_verification: None,
            pending_events: Vec::new(),
            requested_prefix: None,
        }
    }

    /// Construct a builder for an existing SEL at `sel_prefix` and hydrate
    /// owner-local verified state from the **local SAD store only**.
    ///
    /// This is the resume-from-existing-chain constructor — call `new` instead
    /// for inception flows. Mirrors KEL's `KeyEventBuilder::with_dependencies`
    /// (`lib/kels/src/builder.rs`): `sel_completed_verification` walks events
    /// from the local store via `SadStorePageLoader`, runs `SelVerifier::verify_page`,
    /// and produces a token reflecting **owner's view** of the chain. The
    /// server is never consulted at construction.
    ///
    /// Owner-local hydration is the structural fix for the round-9 audit
    /// finding (M1 / L2): a server-driven `sad_verification` could be poisoned
    /// by adversary extension or by a server reporting its tip as owner's tip.
    /// The owner-local design closes that — the cached tip is always one
    /// owner-authored, owner-verified.
    ///
    /// Hydration is attempted only when both `sad_store` and `checker` are
    /// provided. With either missing the builder still latches `sel_prefix`
    /// as `requested_prefix` and skips the local walk; a later
    /// `incept`/`incept_deterministic` that derives a different prefix will be
    /// rejected at `flush` time via the verifier's prefix check.
    ///
    /// `KelsError::NotFound` from the local walk is silently absorbed: the
    /// chain may not exist yet locally (the caller may be about to incept,
    /// or `sad_store` may simply lack the prefix index entry — owner has not
    /// flushed locally). The prefix-mismatch guard remains armed via
    /// `requested_prefix`. Server state is consulted on-demand at action time
    /// (e.g., `repair`, `flush`).
    pub async fn with_prefix(
        sad_client: Option<SadStoreClient>,
        sad_store: Option<Arc<dyn SadStore>>,
        checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
        sel_prefix: &cesr::Digest256,
    ) -> Result<Self, KelsError> {
        let mut builder = Self::new(sad_client, sad_store.clone(), checker.clone());
        builder.requested_prefix = Some(*sel_prefix);
        if let (Some(store), Some(c)) = (sad_store.as_ref(), checker.as_ref()) {
            let mut loader = crate::SadStorePageLoader::new(store.as_ref());
            match crate::sel_completed_verification(
                &mut loader,
                sel_prefix,
                Arc::clone(c),
                crate::page_size(),
                crate::max_pages(),
            )
            .await
            {
                Ok(v) => builder.sad_verification = Some(v),
                // Chain not yet locally inducted — caller may be about to
                // incept, or the local store hasn't seen owner's flushes yet.
                // The prefix-mismatch guard latched on `requested_prefix`
                // catches misuse at flush.
                Err(KelsError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(builder)
    }

    // ==================== Accessors ====================
    //
    // Local-view vs. server-accepted: most accessors below merge `pending_events`
    // (locally staged, not yet authorized) with `sad_verification` (the
    // server-accepted snapshot). Pending values shadow verified ones. This is the
    // right semantic for the builder's own internal users (e.g., `is_established`
    // letting a just-staged `Est` count as established for the next staging
    // call). It is the wrong semantic for any consumer that needs to know what
    // the *server* has accepted — UI display, downstream trust decisions,
    // anything authoritative. Those consumers should query [`sad_verification`]
    // directly. Each accessor's docstring restates this so a reader landing on
    // the method without scrolling up still sees the warning.

    /// Locally staged events not yet flushed to SADStore.
    ///
    /// **Local view.** These events have not been verified server-side. Use
    /// [`sad_verification`](Self::sad_verification) for the authoritative
    /// server-accepted snapshot.
    pub fn pending_events(&self) -> &[SadEvent] {
        &self.pending_events
    }

    /// Verified server-side state, if hydrated via `with_prefix` or produced
    /// by a successful `flush`. `None` for a fresh builder.
    ///
    /// **Authoritative.** This is the server-accepted snapshot — verified
    /// chain state, not a local prediction. Consumers needing trustworthy
    /// state should query this and not the local-view accessors.
    pub fn sad_verification(&self) -> Option<&SelVerification> {
        self.sad_verification.as_ref()
    }

    /// The most recent event on the chain, preferring the pending tail over
    /// the verified tip. `None` if the builder has neither pending nor
    /// verified state.
    ///
    /// **Local view.** When `pending_events` is non-empty, returns a staged
    /// event that has not been verified server-side. Query
    /// [`sad_verification`](Self::sad_verification) for authoritative state.
    pub fn last_event(&self) -> Option<&SadEvent> {
        if let Some(last) = self.pending_events.last() {
            return Some(last);
        }
        self.sad_verification.as_ref().map(|v| v.current_event())
    }

    /// SAID of `last_event()`. Same pending-first precedence.
    ///
    /// **Local view.** May return a SAID for a staged-but-not-yet-verified
    /// event. Query [`sad_verification`](Self::sad_verification) for
    /// authoritative state.
    pub fn last_said(&self) -> Option<&cesr::Digest256> {
        self.last_event().map(|e| &e.said)
    }

    /// SEL prefix of the chain, preferring pending v0 over verified state.
    /// Stable across the chain's lifetime once any inception event exists.
    ///
    /// **Local view.** A staged inception's prefix becomes available here
    /// before the chain is verified server-side. Query
    /// [`sad_verification`](Self::sad_verification) for authoritative state.
    pub fn prefix(&self) -> Option<&cesr::Digest256> {
        if let Some(first) = self.pending_events.first() {
            return Some(&first.prefix);
        }
        self.sad_verification.as_ref().map(|v| v.prefix())
    }

    /// Version of `last_event()`. Same pending-first precedence.
    ///
    /// **Local view.** May reflect a staged-but-not-yet-verified event's
    /// version. Query [`sad_verification`](Self::sad_verification) for
    /// authoritative state.
    pub fn version(&self) -> Option<u64> {
        self.last_event().map(|e| e.version)
    }

    /// The most recently declared or evolved `governance_policy` on the chain,
    /// preferring pending staged events over verified state.
    ///
    /// **Local view.** A pending Evl that proposes a new `governance_policy`
    /// will be reported here even if it would soft-fail the write_policy
    /// check at flush time and not actually advance the server's tracked
    /// policy. Query [`sad_verification`](Self::sad_verification) and read
    /// `governance_policy()` from the token for the server-accepted value.
    pub fn governance_policy(&self) -> Option<cesr::Digest256> {
        for event in self.pending_events.iter().rev() {
            if event.governance_policy.is_some() {
                return event.governance_policy;
            }
            // A pending Evl with None = pure evaluation; keep walking.
        }
        self.sad_verification
            .as_ref()
            .and_then(|v| v.governance_policy().copied())
    }

    /// Whether the chain has `governance_policy` established via either
    /// inception path (Icp-with-gp or Est at v1). `update`, `evaluate`, and
    /// `repair` require this to be true.
    ///
    /// **Local view.** A staged Est makes this `true` immediately, before
    /// the server has accepted the chain. For the authoritative answer use
    /// `sad_verification().and_then(|v| v.governance_policy()).is_some()`.
    pub fn is_established(&self) -> bool {
        self.governance_policy().is_some()
    }

    /// Count of non-evaluation events on the current branch since the last
    /// governance evaluation (Evl or Rpr), or since chain start if none.
    ///
    /// Simulates the verifier's per-branch counter forward through pending
    /// events: `Icp` → 0, `Est` → 1, `Upd` → +1, `Evl`/`Rpr` → 0. The walk
    /// resets on every evaluation event encountered, so a caller that
    /// staged an `Evl` already sees the counter back at zero (plus any
    /// subsequent non-evaluation events).
    ///
    /// Correctness depends on `pending_events` being append-only and only
    /// mutated through this builder's stager methods, which enforce the
    /// kind ordering the simulation assumes (Icp only at position 0, Est
    /// only immediately after Icp, etc.). The field is module-private and
    /// the public API surface preserves that invariant.
    ///
    /// **Local view.** Includes simulated counter advances from staged
    /// events. Query [`sad_verification`](Self::sad_verification) and call
    /// `events_since_evaluation()` on the token for the server-accepted
    /// count.
    pub fn events_since_evaluation(&self) -> usize {
        let mut count = self
            .sad_verification
            .as_ref()
            .map(|v| v.events_since_evaluation())
            .unwrap_or(0);
        for event in &self.pending_events {
            match event.kind {
                SadEventKind::Icp => count = 0,
                SadEventKind::Est => count = 1,
                SadEventKind::Upd => count += 1,
                SadEventKind::Evl | SadEventKind::Rpr => count = 0,
            }
        }
        count
    }

    /// True when the next `Upd` would cross `MAX_NON_EVALUATION_EVENTS` and
    /// therefore requires an `Evl` or `Rpr` first. `update()` returns
    /// `KelsError::EvaluationRequired` in this state.
    ///
    /// **Local view.** Derived from
    /// [`events_since_evaluation`](Self::events_since_evaluation), which
    /// includes pending staged events.
    pub fn needs_evaluation(&self) -> bool {
        self.events_since_evaluation() >= MAX_NON_EVALUATION_EVENTS
    }

    // ==================== Staging (sync) ====================

    /// Stage a v0 `Icp` that declares both `write_policy` and `governance_policy`.
    ///
    /// Consumers of a chain incepted this way cannot recompute the prefix from
    /// `(topic, write_policy)` alone — the v0 SAID depends on
    /// `governance_policy` too. Use `incept_deterministic` when prefix-by-recomputation
    /// (exchange keys, identity chains, anything lookup-driven) is required.
    pub fn incept(
        &mut self,
        topic: impl Into<String>,
        write_policy: cesr::Digest256,
        governance_policy: cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError> {
        self.require_fresh_builder()?;

        let event = SadEvent::icp(topic, write_policy, Some(governance_policy))?;
        let said = event.said;
        self.pending_events.push(event);
        Ok(said)
    }

    /// Stage an atomic `Icp` (v0) + `Est` (v1) pair.
    ///
    /// v0 is bare (`write_policy` only, no governance, no content), so its
    /// SAID is a pure function of `(topic, write_policy)` and consumers can
    /// locate the chain via `compute_sad_event_prefix`. v1 `Est` carries the
    /// `governance_policy` declaration and any optional content. Returns
    /// `(v0_said, v1_said)`. Either both events stage or neither does.
    pub fn incept_deterministic(
        &mut self,
        topic: impl Into<String>,
        write_policy: cesr::Digest256,
        governance_policy: cesr::Digest256,
        content: Option<cesr::Digest256>,
    ) -> Result<(cesr::Digest256, cesr::Digest256), KelsError> {
        self.require_fresh_builder()?;

        // Build both events before mutating state — `SadEvent::icp` and
        // `SadEvent::est` each run `validate_structure` internally, so a
        // structural failure on either leaves `pending_events` empty rather
        // than half-populated.
        let v0 = SadEvent::icp(topic, write_policy, None)?;
        let v1 = SadEvent::est(&v0, content, governance_policy)?;

        let v0_said = v0.said;
        let v1_said = v1.said;
        self.pending_events.push(v0);
        self.pending_events.push(v1);
        Ok((v0_said, v1_said))
    }

    /// Stage an `Upd` carrying new content.
    ///
    /// Requires the chain to be established (governance_policy present). Fails
    /// with `KelsError::EvaluationRequired` when the 63-event bound would be
    /// crossed — caller must stage an `Evl` or `Rpr` first. Fails with
    /// `KelsError::SelDivergent` when the chain is divergent — owner must
    /// stage a `repair` to resolve before further updates, mirroring the
    /// KEL `rec`/`cnt` recovery model.
    pub fn update(&mut self, content: cesr::Digest256) -> Result<cesr::Digest256, KelsError> {
        self.require_established()?;
        self.require_non_divergent()?;

        if self.needs_evaluation() {
            return Err(KelsError::EvaluationRequired);
        }

        let event = SadEvent::upd(self.current_tip()?, content)?;
        let said = event.said;
        self.pending_events.push(event);
        Ok(said)
    }

    /// Stage an `Evl`. All three fields are optional — all-None is a legal
    /// pure evaluation that preserves current-pointer semantics.
    ///
    /// Refuses on divergent chains for symmetry with `update` — the owner
    /// must `repair` first. A pure evaluation on a divergent chain would
    /// pretend the divergence doesn't exist; resolving the fork is the
    /// only meaningful next step.
    pub fn evaluate(
        &mut self,
        content: Option<cesr::Digest256>,
        write_policy: Option<cesr::Digest256>,
        governance_policy: Option<cesr::Digest256>,
    ) -> Result<cesr::Digest256, KelsError> {
        self.require_established()?;
        self.require_non_divergent()?;

        let event = SadEvent::evl(
            self.current_tip()?,
            content,
            write_policy,
            governance_policy,
        )?;
        let said = event.said;
        self.pending_events.push(event);
        Ok(said)
    }

    /// Stage an `Rpr` at the truncation boundary so the server-side
    /// `is_repair` path actually heals divergence or adversarial extension.
    ///
    /// Bypasses `require_non_divergent` — repair is the explicit recovery path,
    /// symmetric to KEL's `recover` / `contest`. Under the round-9 owner-local
    /// design, `sad_verification` is built from the local `sad_store` only;
    /// the cached tip is *always* owner's last authoritative event. Server
    /// state is consulted on-demand here, with both data sources verified
    /// before contributing to the boundary decision.
    ///
    /// **Sequence — verify before deciding.** Every input is verified before
    /// it influences the staged Rpr.
    ///
    /// 1. `sad_verification.policy_satisfied()` — owner's local view passed
    ///    its own policy verification. Disk tampering that re-derived a
    ///    valid SAID for forged content (or KEL-side corruption that breaks
    ///    anchor verification) surfaces here. Refuse with
    ///    `ChainHasUnverifiedEvents`.
    /// 2. `fetch_sel_effective_said(prefix)` — what's the server's tip?
    /// 3. If server tip == owner tip → `NothingToRepair` (chain is clean).
    /// 4. `fetch_tail` + per-event `verify_said + prefix` check (in
    ///    `walk_back_to_first_owner`) catches per-event content forgery.
    /// 5. `SelVerifier::verify_page` over the fetched chain — chain-level
    ///    integrity AND policy verification of the server's view.
    /// 6. If the fetched chain's `policy_satisfied` is false → refuse with
    ///    `ChainHasUnverifiedEvents`. Server is serving events that pass
    ///    SAID integrity but lack KEL anchoring (noise, not a real chain).
    /// 7. `walk_back_to_first_owner` probes `sad_store` for owner's last
    ///    authoritative event — the truncation boundary.
    /// 8. Build Rpr at `version = boundary.version + 1`,
    ///    `previous = boundary.said`.
    ///
    /// Two `policy_satisfied` gates fire — one on owner's local view (step 1),
    /// one on the server's view (step 6). They guard different data sources;
    /// neither is redundant.
    ///
    /// **Authoritative source split.** `sad_store` is the authoritative
    /// source for "is this event owner-authored?" — never the server. The
    /// server provides the chain segment for traversal; per-event SAID
    /// verification + chain-level `verify_page` catches substitution
    /// attacks. Letting the server influence the boundary decision (e.g.,
    /// trusting an adversary's stored event as a "boundary candidate")
    /// would allow an adversary's events into the truncation point —
    /// that's the wrong direction.
    ///
    /// Returns `NothingToRepair` when server agrees with owner's tip (no
    /// repair needed). Returns `ChainHasUnverifiedEvents` when either
    /// policy gate fails. Requires `sad_store: Some(_)` and
    /// `sad_client: Some(_)` — owner-local boundary oracle and on-demand
    /// server consultation.
    pub async fn repair(
        &mut self,
        content: Option<cesr::Digest256>,
    ) -> Result<cesr::Digest256, KelsError> {
        self.require_established()?;

        let sad_store = self
            .sad_store
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("repair requires a sad_store".into()))?;

        let sad_client = self.sad_client.as_ref().ok_or_else(|| {
            KelsError::OfflineMode(
                "repair requires a SadStoreClient — server's effective_said \
                 must be consulted on-demand to determine whether anything \
                 needs repairing"
                    .into(),
            )
        })?;

        let checker = self.checker.as_ref().ok_or_else(|| {
            KelsError::OfflineMode(
                "repair requires a PolicyChecker — fetched chain must be \
                 verified end-to-end before contributing to the boundary \
                 decision"
                    .into(),
            )
        })?;

        let verification = self
            .sad_verification
            .as_ref()
            .ok_or(KelsError::NotIncepted)?;

        // Step 1 — gate on owner's local view. Owner-local sad_verification
        // can fail policy via disk tampering that recomputed valid SAIDs
        // for forged content (passes verify_said but breaks KEL anchoring).
        if !verification.policy_satisfied() {
            return Err(KelsError::ChainHasUnverifiedEvents(
                "owner-local sad_verification reports policy_satisfied=false — \
                 local store may have been tampered, or KEL anchors are \
                 unreachable; resolve before repairing"
                    .into(),
            ));
        }

        let owner_tip = verification.current_event().clone();
        let prefix = owner_tip.prefix;

        // Step 2 — what's the server's view of the tip?
        let server_effective = sad_client
            .fetch_sel_effective_said(&prefix)
            .await?
            .ok_or_else(|| {
                KelsError::NotFound(format!(
                    "server has no chain at prefix {} — nothing to repair against",
                    prefix
                ))
            })?;
        let (server_said_str, _server_divergent) = server_effective;
        let server_said = cesr::Digest256::from_qb64(&server_said_str).map_err(|e| {
            KelsError::VerificationFailed(format!(
                "server effective_said {} is not a valid Digest256: {}",
                server_said_str, e
            ))
        })?;

        // Step 3 — if server agrees with owner's tip, nothing to repair.
        if server_said == owner_tip.said {
            return Err(KelsError::NothingToRepair);
        }

        // Step 4 + 5 — fetch server's tail and run a full SelVerifier over
        // it. `verify_page` calls `verify_event` per event, which runs
        // `event.verify_said()` and the prefix check — covers step 4's
        // per-event integrity guarantee. `finish()` produces a verified
        // token whose `policy_satisfied` flag covers step 5's chain-level
        // policy check.
        let sad_source = sad_client.as_sad_source()?;
        let fetched_tail = sad_source
            .fetch_tail(&prefix, crate::MINIMUM_PAGE_SIZE)
            .await?;
        if fetched_tail.is_empty() {
            return Err(KelsError::NotFound(format!(
                "server tail empty for prefix {} — nothing to repair against",
                prefix
            )));
        }
        let mut fetched_verifier = SelVerifier::new(Some(&prefix), Arc::clone(checker));
        fetched_verifier.verify_page(&fetched_tail).await?;
        let fetched_verification = fetched_verifier.finish().await?;

        // Step 6 — gate on server view's policy. If the server is serving
        // forged events that pass per-event verify_said but lack KEL
        // anchoring, the policy check fails and we refuse.
        if !fetched_verification.policy_satisfied() {
            return Err(KelsError::ChainHasUnverifiedEvents(
                "server-fetched chain reports policy_satisfied=false — \
                 server is serving events without valid KEL anchoring; \
                 will not repair against unverified data"
                    .into(),
            ));
        }

        // Step 7 — walk back through the verified tail, starting from server's
        // tip. Probe sad_store at each step; first hit is owner's last
        // authoritative event = boundary. The chain map is pre-verified
        // (verify_page above), so traversing `previous` links there is sound.
        let server_tip = fetched_verification.current_event().clone();
        let chain: HashMap<cesr::Digest256, SadEvent> =
            fetched_tail.iter().map(|e| (e.said, e.clone())).collect();
        let boundary = walk_back_to_first_owner(sad_store, &chain, &server_tip).await?;

        // Step 8 — stage Rpr at boundary.version + 1, previous = boundary.said.
        let rpr = SadEvent::rpr(&boundary, content)?;
        let said = rpr.said;
        self.pending_events.push(rpr);
        Ok(said)
    }

    // ==================== Submission (async) ====================

    /// Publish staged events as generic SAD objects in the object store.
    ///
    /// Makes every pending event fetchable by SAID before any anchoring
    /// happens — the distribution channel for multi-party review. Idempotent:
    /// the object store keys by SAID, so repeated calls from one or multiple
    /// parties are safe. Does not promote events into the SEL — `flush()`
    /// still does that.
    ///
    /// Does NOT write to the local `sad_store` — local cache writes happen in
    /// `flush` after the events are verified server-side. Pre-flush events
    /// stay in `pending_events` only.
    pub async fn publish_pending(&self) -> Result<(), KelsError> {
        let client = self.sad_client.as_ref().ok_or_else(|| {
            KelsError::OfflineMode("publish_pending requires a SadStoreClient".into())
        })?;

        for event in &self.pending_events {
            let value = serde_json::to_value(event)?;
            client.post_sad_object(&value).await?;
        }
        Ok(())
    }

    /// Submit pending events to SADStore, then absorb into verified state.
    ///
    /// No anchoring — callers have already run `kel_builder.interact(&said)`
    /// for each returned SAID. On success, absorbs pending into
    /// `sad_verification` via `SelVerifier::resume` + `verify_page` + `finish`,
    /// then clears `pending_events`.
    ///
    /// **Failure semantics.** Three internal phases run in order:
    ///
    /// 1. `sad_client.submit_sad_events(...)` — server commits the batch.
    /// 2. `sad_store.store(...)` per event — local write-through cache.
    /// 3. `absorb_pending()` — re-verify pending against `self.checker` and
    ///    roll into `sad_verification`, then clear pending.
    ///
    /// An error from phase 1 means nothing was committed server-side; the
    /// builder is unchanged and the caller can retry or discard. An error
    /// from phase 2 or 3 means the events **are on the server** but the
    /// builder's local state was not advanced: `pending_events` is still
    /// populated and `sad_verification` is stale. The caller cannot tell
    /// these apart from the `Err` alone.
    ///
    /// **Retry transient errors rather than discarding pending.** All three
    /// phases are idempotent: `submit_sad_events` deduplicates by SAID,
    /// `sad_store.store` overwrites under the same key, and `absorb_pending`
    /// re-verifies from current server state. A retry after a phase-1
    /// failure resubmits cleanly; a retry after a phase-2 or phase-3
    /// failure no-ops on the server side and converges the builder's
    /// local view.
    ///
    /// Structural errors that survive retry (e.g., a verifier-internal
    /// invariant violation that fires identically on every attempt) are
    /// bugs — file an issue rather than retrying indefinitely.
    ///
    /// **Divergence signal.** The server's `submit_sad_events` response
    /// carries `diverged_at: Option<u64>` — populated when a concurrent
    /// writer's fork is observed at submit time. The local `absorb_pending`
    /// processes only the owner's pending batch, so it cannot detect such a
    /// fork. On success, the server-reported value is stamped onto
    /// `sad_verification.diverged_at_version()` (with `or_else` semantics:
    /// only when the local detection didn't already produce `Some(_)`) and
    /// surfaced via [`FlushOutcome::diverged_at_at_submit`]. Subsequent
    /// `update` / `evaluate` calls refuse with `KelsError::SelDivergent`
    /// until the owner stages a `repair`.
    ///
    /// Returns `KelsError::OfflineMode` when `sad_client` is `None`, or when
    /// pending events exist but `checker` was not supplied at construction.
    pub async fn flush(&mut self) -> Result<FlushOutcome, KelsError> {
        if self.pending_events.is_empty() {
            return Ok(FlushOutcome {
                diverged_at_at_submit: None,
                applied: false,
            });
        }

        let client = self
            .sad_client
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("flush requires a SadStoreClient".into()))?;

        // Fail fast: absorb_pending needs a checker. Validate before any side
        // effects so we don't submit + persist locally and then strand pending
        // on a no-checker error with no in-place recovery path.
        if self.checker.is_none() {
            return Err(KelsError::OfflineMode(
                "flush requires a PolicyChecker".into(),
            ));
        }

        let response = client.submit_sad_events(&self.pending_events).await?;

        // Write to local cache before absorbing — events are already
        // server-accepted (phase 1 succeeded), so the cache reflects committed
        // state. `store_sel_event` populates both the SAID-keyed payload AND
        // the per-prefix index that `load_sel_events` (and thus
        // `with_prefix`'s owner-local hydration path) consumes. Owner's events
        // get into the prefix-indexed view automatically as they're flushed.
        // If absorb_pending later fails, the cache is fine: it holds events
        // that any subsequent `with_prefix()` will re-verify locally.
        if let Some(store) = self.sad_store.as_ref() {
            for event in &self.pending_events {
                store.store_sel_event(event).await?;
            }
        }

        // Repair flushes need a fresh server fetch, not incremental absorb.
        // The Rpr's `previous` points at a pre-truncation event that isn't a
        // current branch tip in the cached token, so `SelVerifier::resume` +
        // `verify_page` would error ("previous does not match any branch
        // tip"). After the server's `is_repair` truncation the chain is
        // linear from v0 to the Rpr; re-hydrate from the **local** SAD store
        // via `sel_completed_verification` (mirrors `with_prefix`'s owner-
        // local path) — the prefix index now contains owner's pre-repair
        // events plus the freshly-stored Rpr, so the local view is the
        // post-repair owner-authored chain. No server round-trip on this
        // path; non-repair flushes keep the incremental-absorb fast path.
        let was_repair = self.pending_events.iter().any(|e| e.kind.is_repair());

        if was_repair {
            #[allow(clippy::expect_used)]
            // Repair built from this builder's verification; prefix is set.
            let prefix = *self
                .prefix()
                .expect("repair flush has prefix from pending or verification");
            #[allow(clippy::expect_used)]
            // Already-checked above; checker.is_none() returned early.
            let checker = Arc::clone(
                self.checker
                    .as_ref()
                    .expect("flush is_none-checked checker above"),
            );
            #[allow(clippy::expect_used)]
            // Repair's pre-flight already requires sad_store at the top of
            // `repair()`; getting here means the store is present.
            let store = self
                .sad_store
                .as_ref()
                .expect("repair flush requires sad_store (validated by repair pre-flight)");
            let mut loader = crate::SadStorePageLoader::new(store.as_ref());
            let fresh = crate::sel_completed_verification(
                &mut loader,
                &prefix,
                checker,
                crate::page_size(),
                crate::max_pages(),
            )
            .await?;
            self.sad_verification = Some(fresh);
            self.pending_events.clear();
        } else {
            self.absorb_pending().await?;

            // Stamp the server-reported divergence onto the local token. The
            // local verifier only saw the owner's batch, so its
            // `diverged_at_version` would be `None` even when the server has
            // two branches at this version. This is record-keeping, not
            // recovery — the owner calls `repair` themselves when they're
            // ready, exactly as they'd call `rec`/`cnt` on a divergent KEL
            // today. Skip on repair: post-repair the server chain is linear,
            // and the fresh hydrate already reflects that.
            if let Some(at) = response.diverged_at
                && let Some(v) = self.sad_verification.as_mut()
            {
                v.set_diverged_at_version(at);
            }
        }

        Ok(FlushOutcome {
            diverged_at_at_submit: response.diverged_at,
            applied: response.applied,
        })
    }

    // ==================== Private helpers ====================

    fn require_fresh_builder(&self) -> Result<(), KelsError> {
        if !self.pending_events.is_empty() || self.sad_verification.is_some() {
            return Err(KelsError::InvalidKel(
                "Inception requires an empty builder (no pending or verified state)".into(),
            ));
        }
        Ok(())
    }

    fn require_established(&self) -> Result<(), KelsError> {
        if !self.is_established() {
            return Err(KelsError::InvalidKel(
                "Chain not established — incept (with governance) or incept_deterministic first"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Refuse staging on a divergent chain. `repair` is the only legal next
    /// staging operation — analogous to how a divergent KEL refuses normal
    /// rotations until the owner runs `recover` or `contest`. The owner has
    /// to explicitly choose recovery; nothing happens automatically.
    fn require_non_divergent(&self) -> Result<(), KelsError> {
        if let Some(v) = self.sad_verification.as_ref()
            && let Some(at) = v.diverged_at_version()
        {
            return Err(KelsError::SelDivergent { at });
        }
        Ok(())
    }

    fn current_tip(&self) -> Result<&SadEvent, KelsError> {
        self.last_event().ok_or(KelsError::NotIncepted)
    }

    /// Fold pending events into verified state via `SelVerifier::resume`.
    async fn absorb_pending(&mut self) -> Result<(), KelsError> {
        if self.pending_events.is_empty() {
            return Ok(());
        }

        let checker = self
            .checker
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("flush requires a PolicyChecker".into()))?;

        // `requested_prefix` is the authoritative expectation when hydrated via
        // `with_prefix`. On a fresh builder it's None — the verifier latches
        // to the inception event's prefix, and subsequent events get checked
        // against that.
        let mut verifier = if let Some(ref v) = self.sad_verification {
            SelVerifier::resume(v, Arc::clone(checker))?
        } else {
            SelVerifier::new(self.requested_prefix.as_ref(), Arc::clone(checker))
        };

        verifier.verify_page(&self.pending_events).await?;
        self.sad_verification = Some(verifier.finish().await?);
        self.pending_events.clear();
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::types::{PagedSadSource, SadEvent};

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
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

    const TEST_TOPIC: &str = "kels/sad/v1/keys/mlkem";

    #[test]
    fn incept_stages_single_v0_with_governance() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        let said = b.incept(TEST_TOPIC, wp, gp).unwrap();

        assert_eq!(b.pending_events().len(), 1);
        let v0 = &b.pending_events()[0];
        assert_eq!(v0.said, said);
        assert_eq!(v0.version, 0);
        assert_eq!(v0.kind, SadEventKind::Icp);
        assert_eq!(v0.write_policy, Some(wp));
        assert_eq!(v0.governance_policy, Some(gp));
        assert!(v0.content.is_none());
        assert!(b.is_established());
    }

    #[test]
    fn incept_deterministic_stages_atomic_v0_v1_pair() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let content = test_digest(b"content");
        let mut b = SadEventBuilder::new(None, None, None);
        let (v0_said, v1_said) = b
            .incept_deterministic(TEST_TOPIC, wp, gp, Some(content))
            .unwrap();

        assert_eq!(b.pending_events().len(), 2);
        let v0 = &b.pending_events()[0];
        assert_eq!(v0.said, v0_said);
        assert_eq!(v0.version, 0);
        assert_eq!(v0.kind, SadEventKind::Icp);
        assert_eq!(v0.write_policy, Some(wp));
        assert!(v0.governance_policy.is_none());

        let v1 = &b.pending_events()[1];
        assert_eq!(v1.said, v1_said);
        assert_eq!(v1.version, 1);
        assert_eq!(v1.kind, SadEventKind::Est);
        assert!(v1.write_policy.is_none());
        assert_eq!(v1.governance_policy, Some(gp));
        assert_eq!(v1.content, Some(content));

        // v0 SAID must equal the deterministic prefix-derivation path so
        // external consumers can recompute the chain location without fetching.
        let expected_prefix = crate::compute_sad_event_prefix(wp, TEST_TOPIC).unwrap();
        assert_eq!(v0.prefix, expected_prefix);
        assert_eq!(v1.prefix, expected_prefix);
    }

    /// Regression guard for the `incept` vs `incept_deterministic` distinction:
    /// `incept` puts governance on v0, so the v0 SAID depends on it and the
    /// chain prefix is NOT recoverable from `(topic, write_policy)` alone.
    /// `incept_deterministic` keeps v0 bare so the prefix matches
    /// `compute_sad_event_prefix`. If these ever converge silently the
    /// lookup-driven flows (exchange keys, identity chains) break.
    #[test]
    fn incept_prefix_diverges_from_compute_sad_event_prefix() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept(TEST_TOPIC, wp, gp).unwrap();
        let v0_prefix = b.pending_events()[0].prefix;

        let lookup_prefix = crate::compute_sad_event_prefix(wp, TEST_TOPIC).unwrap();
        assert_ne!(
            v0_prefix, lookup_prefix,
            "incept(governance on v0) must NOT match the deterministic-lookup prefix; \
             callers needing prefix recomputation must use incept_deterministic"
        );

        // And the deterministic variant DOES match — the symmetric assertion
        // already lives in incept_deterministic_stages_atomic_v0_v1_pair, but
        // restating it here keeps both halves of the contract visible at a glance.
        let mut b2 = SadEventBuilder::new(None, None, None);
        b2.incept_deterministic(TEST_TOPIC, wp, gp, None).unwrap();
        assert_eq!(b2.pending_events()[0].prefix, lookup_prefix);
    }

    #[test]
    fn second_inception_rejected() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept(TEST_TOPIC, wp, gp).unwrap();

        let err = b.incept(TEST_TOPIC, wp, gp).unwrap_err();
        assert!(matches!(err, KelsError::InvalidKel(_)));
        let err = b
            .incept_deterministic(TEST_TOPIC, wp, gp, None)
            .unwrap_err();
        assert!(matches!(err, KelsError::InvalidKel(_)));
    }

    #[test]
    fn update_requires_established_chain() {
        let mut b = SadEventBuilder::new(None, None, None);
        let err = b.update(test_digest(b"c")).unwrap_err();
        assert!(matches!(err, KelsError::InvalidKel(_)));
    }

    #[test]
    fn update_after_incept_deterministic_chains_correctly() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        let (_v0, v1_said) = b.incept_deterministic(TEST_TOPIC, wp, gp, None).unwrap();

        let content = test_digest(b"payload");
        let upd_said = b.update(content).unwrap();
        assert_eq!(b.pending_events().len(), 3);
        let upd = &b.pending_events()[2];
        assert_eq!(upd.said, upd_said);
        assert_eq!(upd.version, 2);
        assert_eq!(upd.kind, SadEventKind::Upd);
        assert_eq!(upd.previous, Some(v1_said));
        assert_eq!(upd.content, Some(content));
        assert!(upd.write_policy.is_none());
        assert!(upd.governance_policy.is_none());
    }

    #[test]
    fn evaluate_resets_counter_and_preserves_content() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept(TEST_TOPIC, wp, gp).unwrap();

        // Icp is at counter 0; subsequent updates accrue.
        b.update(test_digest(b"c1")).unwrap();
        b.update(test_digest(b"c2")).unwrap();
        assert_eq!(b.events_since_evaluation(), 2);

        b.evaluate(None, None, None).unwrap();
        // Pure-evaluation Evl resets the counter to zero even though it's in
        // pending — this is what keeps update() from erroring unnecessarily
        // when the caller has already staged the remediation.
        assert_eq!(b.events_since_evaluation(), 0);

        b.update(test_digest(b"c3")).unwrap();
        assert_eq!(b.events_since_evaluation(), 1);
    }

    #[test]
    fn update_errors_at_63_event_bound() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept(TEST_TOPIC, wp, gp).unwrap();
        // Icp sets counter to 0. 63 updates bring it to 63 (the bound).
        for i in 0..MAX_NON_EVALUATION_EVENTS {
            let content = test_digest(format!("c{}", i).as_bytes());
            b.update(content).unwrap();
        }
        assert_eq!(b.events_since_evaluation(), MAX_NON_EVALUATION_EVENTS);
        assert!(b.needs_evaluation());

        let err = b.update(test_digest(b"overflow")).unwrap_err();
        assert!(matches!(err, KelsError::EvaluationRequired));

        // Evaluate → counter resets → next update succeeds.
        b.evaluate(None, None, None).unwrap();
        b.update(test_digest(b"after-eval")).unwrap();
    }

    // Pre-M1-followup, `repair` extended the tip on any chain (including
    // clean chains). The new contract: repair is for actual healing —
    // divergent or adversarially-extended chains. Clean chains return
    // `NothingToRepair`. The "stage an Rpr from tip" semantic is gone;
    // tests covering Rpr verification are pinned by the new
    // `repair_at_*` tests below and the full-stack tests in sad_builder_tests.rs.

    #[test]
    fn incept_deterministic_without_establish_content_ok() {
        // Content on Est is optional — omitting it still produces a valid chain.
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept_deterministic(TEST_TOPIC, test_digest(b"wp"), test_digest(b"gp"), None)
            .unwrap();
        assert_eq!(b.pending_events().len(), 2);
        assert!(b.pending_events()[1].content.is_none());
    }

    /// Happy path: incept_deterministic → update → evaluate → update,
    /// verified end-to-end against a fresh `SelVerifier` to confirm every
    /// staged event is structurally sound and correctly chained. Repair is
    /// not exercised here — a clean chain returns `NothingToRepair`; Rpr
    /// verification is covered by the dedicated `repair_at_*` tests.
    #[tokio::test]
    async fn staged_chain_verifies_from_scratch() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept_deterministic(TEST_TOPIC, wp, gp, Some(test_digest(b"c1")))
            .unwrap();
        b.update(test_digest(b"c2")).unwrap();
        b.evaluate(Some(test_digest(b"c3")), None, None).unwrap();
        b.update(test_digest(b"c4")).unwrap();
        b.evaluate(Some(test_digest(b"c5")), None, None).unwrap();

        let prefix = *b.prefix().unwrap();
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&prefix), Arc::clone(&checker));
        verifier
            .verify_page(b.pending_events())
            .await
            .expect("staged chain verifies");
        let verification = verifier.finish().await.expect("verification finishes");
        assert_eq!(verification.current_event().version, 5);
        assert_eq!(verification.current_event().kind, SadEventKind::Evl);
    }

    /// A builder constructed with `with_prefix(sel_prefix = X)` must reject
    /// an inception whose derived prefix doesn't equal X. Closes the
    /// silent-state-drift footgun where a caller asked for chain X and the
    /// builder happily initialized chain Y instead.
    #[tokio::test]
    async fn requested_prefix_mismatch_rejected_at_absorb() {
        use crate::compute_sad_event_prefix;

        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        // Expected prefix derived from a *different* write_policy than the one
        // the caller will use for inception. `with_prefix` treats this as
        // "the chain I expect to operate on"; the later incept_deterministic
        // will derive from `wp`, giving a distinct prefix.
        let wrong_wp = test_digest(b"wrong-wp");
        let expected_prefix = compute_sad_event_prefix(wrong_wp, TEST_TOPIC).unwrap();
        let actual_prefix = compute_sad_event_prefix(wp, TEST_TOPIC).unwrap();
        assert_ne!(expected_prefix, actual_prefix, "test-setup invariant");

        // sad_client=None skips the server hydration round-trip. The only
        // observable effect of `with_prefix` here is that `requested_prefix`
        // gets latched. The checker is required so absorb_pending has one to
        // hand to the verifier.
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut b =
            SadEventBuilder::with_prefix(None, None, Some(Arc::clone(&checker)), &expected_prefix)
                .await
                .unwrap();

        b.incept_deterministic(TEST_TOPIC, wp, gp, None).unwrap();

        let err = b.absorb_pending().await.unwrap_err();
        match err {
            KelsError::VerificationFailed(msg) => {
                assert!(
                    msg.contains("doesn't match SEL prefix"),
                    "Expected prefix-mismatch message, got: {msg}"
                );
            }
            other => panic!("Expected VerificationFailed, got: {other:?}"),
        }
    }

    // The pre-round-9 `repair_at_divergence_version` test is gone. Under the
    // owner-local rework, divergence-on-the-server is a state owner detects
    // via `fetch_sel_effective_said` at repair time — there is no divergent
    // cached token in the owner-local model. The end-to-end contract is
    // covered by `flush_repair_heals_divergent_chain` in
    // `services/sadstore/tests/sad_builder_tests.rs`.

    /// In-memory `PagedSadSource` for unit-testing the Case B walk. Mirrors
    /// production semantics: `since` is **strictly exclusive** (server returns
    /// events at `(version, said) > since`'s position), `fetch_tail` returns
    /// the last `limit` events ordered by `(version ASC, said ASC)`.
    ///
    /// Distinct from `lib/kels/src/types/sad/sync.rs`'s `PagedVecSadSource`,
    /// which is the paginated-only variant used by divergence-detection tests
    /// and does not implement `fetch_tail`.
    struct RepairTestSadSource {
        events: Vec<SadEvent>,
    }
    #[async_trait::async_trait]
    impl crate::types::PagedSadSource for RepairTestSadSource {
        async fn fetch_page(
            &self,
            _prefix: &cesr::Digest256,
            since: Option<&cesr::Digest256>,
            limit: usize,
        ) -> Result<(Vec<SadEvent>, bool), KelsError> {
            // `since` semantics in production (`services/sadstore/src/repository.rs:374-410`):
            // strictly `(version, said) > since`. Match that here so the mock
            // doesn't silently double-count entries at page boundaries.
            let start_idx = match since {
                Some(s) => self
                    .events
                    .iter()
                    .position(|e| e.said == *s)
                    .map(|i| i + 1)
                    .unwrap_or(0),
                None => 0,
            };
            let end_idx = (start_idx + limit).min(self.events.len());
            let events: Vec<SadEvent> = self.events[start_idx..end_idx].to_vec();
            let has_more = end_idx < self.events.len();
            Ok((events, has_more))
        }

        async fn fetch_tail(
            &self,
            _prefix: &cesr::Digest256,
            limit: usize,
        ) -> Result<Vec<SadEvent>, KelsError> {
            // Production semantics: last `limit` events ordered by
            // `(version DESC, said DESC)`, then reversed before return so the
            // caller sees `(version ASC, said ASC)`. Since these test events
            // are stored sorted by version, taking the suffix of `limit` is
            // equivalent.
            let start = self.events.len().saturating_sub(limit);
            Ok(self.events[start..].to_vec())
        }
    }

    /// Build owner+adversary linear-chain fixture for Case B tests:
    /// owner authored v0..vK, adversary appended v(K+1)..vT. Returns
    /// `(prefix, events_v0_to_vT, sad_store_with_owner_events_only,
    /// owner_token_at_vT)`. The token is verified across the full
    /// adversary-extended chain so cached_tip == vT.
    async fn build_adversary_extension_fixture(
        owner_count: usize,
        adversary_count: usize,
    ) -> (
        cesr::Digest256,
        Vec<SadEvent>,
        Arc<dyn SadStore>,
        SelVerification,
    ) {
        use crate::store::InMemorySadStore;
        assert!(
            owner_count >= 2,
            "need at least v0 (Icp) + vK (Upd or beyond)"
        );
        assert!(adversary_count >= 1, "need at least one adversary event");

        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut events = Vec::new();
        let v0 = SadEvent::icp(TEST_TOPIC, wp, Some(gp)).unwrap();
        events.push(v0.clone());
        for i in 1..owner_count {
            let prev = events.last().unwrap();
            let event =
                SadEvent::upd(prev, test_digest(format!("owner-{}", i).as_bytes())).unwrap();
            events.push(event);
        }
        for i in 0..adversary_count {
            let prev = events.last().unwrap();
            let event =
                SadEvent::upd(prev, test_digest(format!("adversary-{}", i).as_bytes())).unwrap();
            events.push(event);
        }

        // Owner's local store has only owner-authored events (v0..v(K)).
        let store: Arc<dyn SadStore> = Arc::new(InMemorySadStore::new());
        for event in &events[..owner_count] {
            store.store_sel_event(event).await.unwrap();
        }

        // Verify full adversary-extended chain to produce a token whose
        // current_event is the adversary's tip vT.
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier.verify_page(&events).await.unwrap();
        let token = verifier.finish().await.unwrap();
        assert_eq!(token.diverged_at_version(), None);
        assert_eq!(token.current_event().said, events.last().unwrap().said);

        (v0.prefix, events, store, token)
    }

    /// `repair` on a linear chain extended by an adversary by ONE event
    /// stages an Rpr at `v(K+1)` where `vK` is owner's last authoritative
    /// event. The walk-back finds vK at the first probe.
    ///
    /// Under the round-9 owner-local rework, `walk_back_to_first_owner` takes
    /// a pre-verified in-memory chain map (built by the caller from a
    /// `SelVerifier::verify_page`-validated tail). The unit test passes the
    /// fixture's events directly into the map; the full-stack tests
    /// (`flush_repair_heals_*`) exercise the fetch+verify path end-to-end.
    #[tokio::test]
    async fn repair_at_adversarial_extension_boundary() {
        // owner: v0 + v1 (K=1); adversary: v2 (T=2). T-K = 1.
        let (_prefix, events, store, _token) = build_adversary_extension_fixture(2, 1).await;
        let v1_owner_said = events[1].said;

        let chain: HashMap<cesr::Digest256, SadEvent> =
            events.iter().map(|e| (e.said, e.clone())).collect();

        let boundary = super::walk_back_to_first_owner(&store, &chain, events.last().unwrap())
            .await
            .expect("walk finds owner boundary at vK = v1");
        assert_eq!(boundary.said, v1_owner_said);
        assert_eq!(boundary.version, 1);

        // Sanity assertion on what an Rpr built from `boundary` looks like.
        let rpr = SadEvent::rpr(&boundary, Some(test_digest(b"repaired-content"))).unwrap();
        assert_eq!(rpr.kind, SadEventKind::Rpr);
        assert_eq!(rpr.version, 2);
        assert_eq!(rpr.previous, Some(v1_owner_said));
    }

    /// `repair` on a linear chain extended by the adversary by MORE THAN
    /// ONE event still finds the owner's boundary — the walk uses the
    /// server-fetched chain segment as an in-memory map for `previous`-link
    /// traversal of adversary events, and probes `sad_store` at each step
    /// for the owner-authored boundary. Pins the page-fetch + in-memory walk
    /// shape introduced in the M1-followup multi-step extension.
    #[tokio::test]
    async fn repair_at_adversarial_extension_boundary_multi_step() {
        // owner: v0 + v1 (K=1); adversary: v2..v5 (4 events). T-K = 4.
        let (_prefix, events, store, _token) = build_adversary_extension_fixture(2, 4).await;
        let v1_owner_said = events[1].said;

        let chain: HashMap<cesr::Digest256, SadEvent> =
            events.iter().map(|e| (e.said, e.clone())).collect();

        let boundary = super::walk_back_to_first_owner(&store, &chain, events.last().unwrap())
            .await
            .expect("walk finds owner boundary across multi-step adversary extension");
        assert_eq!(
            boundary.said, v1_owner_said,
            "boundary must be vK (owner's last) regardless of adversary extension length"
        );
        assert_eq!(boundary.version, 1);

        // Sanity assertion on what an Rpr built from `boundary` looks like.
        let rpr = SadEvent::rpr(&boundary, Some(test_digest(b"repaired-content"))).unwrap();
        assert_eq!(rpr.version, 2, "Rpr at v(K+1) = v2 regardless of T-K");
        assert_eq!(rpr.previous, Some(v1_owner_said));
    }

    // The pre-round-9 `repair_clean_state_errors` unit test is gone. Under the
    // owner-local rework, `NothingToRepair` is determined by comparing owner's
    // tip against `SadStoreClient::fetch_sel_effective_said` — requires a real
    // (or stub) HTTP client that the unit-level harness can't easily provide.
    // The full-stack contract is covered end-to-end against a live sadstore in
    // `services/sadstore/tests/sad_builder_tests.rs`.

    /// Pin `RepairTestSadSource::fetch_page`'s exclusive-`since` semantics —
    /// the pagination contract `walk_back_to_first_owner` and
    /// `transfer_sad_events` depend on. With production-matching semantics,
    /// paging through with `since = last_said` yields strictly disjoint pages;
    /// pre-fix (inclusive `since`), pages overlapped by one event at the
    /// boundary. The test fails under the inclusive impl and passes under
    /// exclusive.
    #[tokio::test]
    async fn vec_sad_source_pagination_exclusive_since() {
        let (prefix, events, _store, _token) = build_adversary_extension_fixture(2, 4).await;
        let source = RepairTestSadSource {
            events: events.clone(),
        };
        let total = events.len();
        assert!(
            total >= 5,
            "fixture invariant: chain must be long enough to paginate"
        );

        // Page 1: from start, limit=2. Should return [v0, v1] with has_more=true.
        let (page1, has_more_1) = source.fetch_page(&prefix, None, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].said, events[0].said);
        assert_eq!(page1[1].said, events[1].said);
        assert!(has_more_1);

        // Page 2: since = last said of page 1 (v1). Exclusive semantics → page
        // starts at v2, NOT v1. Returns [v2, v3] with has_more=true (more left).
        let (page2, has_more_2) = source
            .fetch_page(&prefix, Some(&page1.last().unwrap().said), 2)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(
            page2[0].said, events[2].said,
            "exclusive `since`: next page must start AFTER the cursor, not AT it"
        );
        assert_eq!(page2[1].said, events[3].said);
        assert!(has_more_2);

        // Page 3: since = last of page 2 (v3). Returns the rest [v4, v5] with has_more=false.
        let (page3, has_more_3) = source
            .fetch_page(&prefix, Some(&page2.last().unwrap().said), 2)
            .await
            .unwrap();
        assert_eq!(page3.len(), 2);
        assert_eq!(page3[0].said, events[4].said);
        assert_eq!(page3[1].said, events[5].said);
        assert!(!has_more_3);

        // The three pages must be strictly disjoint: a flatten produces the
        // chain in order with no duplicates and no gaps.
        let mut all = page1.clone();
        all.extend(page2.clone());
        all.extend(page3.clone());
        assert_eq!(all.len(), total);
        for (i, event) in all.iter().enumerate() {
            assert_eq!(event.said, events[i].said, "page {i} mismatch");
        }
    }

    /// `repair` errors cleanly when the builder has no `sad_store` configured —
    /// the walk needs a probe oracle to distinguish owner's events from the
    /// server's. No silent fallback (would let adversary-influenced data into
    /// the boundary decision).
    #[tokio::test]
    async fn repair_without_sad_store_errors() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let v0 = SadEvent::icp(TEST_TOPIC, wp, Some(gp)).unwrap();
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier
            .verify_page(std::slice::from_ref(&v0))
            .await
            .unwrap();
        let token = verifier.finish().await.unwrap();

        let mut b = SadEventBuilder::new(None, None, Some(Arc::clone(&checker)));
        b.sad_verification = Some(token);

        let err = b
            .repair(Some(test_digest(b"content")))
            .await
            .expect_err("repair must error without a sad_store");
        assert!(
            matches!(err, KelsError::OfflineMode(_)),
            "Expected OfflineMode, got: {err:?}"
        );
    }

    /// `with_prefix` derives owner's tip from the **local store only** —
    /// `sel_completed_verification` walks the prefix index and produces a
    /// token whose `current_event` matches owner's last `store_sel_event`
    /// call. No server consultation at construction (round-9 owner-local
    /// rework).
    #[tokio::test]
    async fn with_prefix_derives_owner_tip_from_local_store_only() {
        use crate::store::InMemorySadStore;

        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let v0 = SadEvent::icp(TEST_TOPIC, wp, Some(gp)).unwrap();
        let v1 = SadEvent::upd(&v0, test_digest(b"content-1")).unwrap();
        let v2 = SadEvent::upd(&v1, test_digest(b"content-2")).unwrap();

        // Owner's local store: v0 + v1 + v2 (all owner-authored).
        let store: Arc<dyn SadStore> = Arc::new(InMemorySadStore::new());
        store.store_sel_event(&v0).await.unwrap();
        store.store_sel_event(&v1).await.unwrap();
        store.store_sel_event(&v2).await.unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        // sad_client = None so we *can't* consult the server even if we tried.
        // Round-9 owner-local: hydration walks `store` only.
        let b =
            SadEventBuilder::with_prefix(None, Some(Arc::clone(&store)), Some(checker), &v0.prefix)
                .await
                .expect("with_prefix hydrates owner-local from store");

        let v = b.sad_verification().expect("hydrated");
        assert_eq!(
            v.current_event().said,
            v2.said,
            "current_event is owner's last `store_sel_event` write (v2)"
        );
        assert_eq!(v.current_event().version, 2);
        assert_eq!(v.branches().len(), 1, "single owner branch");
        assert_eq!(v.diverged_at_version(), None);
        assert!(b.pending_events().is_empty());
    }

    /// `with_prefix` returns an empty builder when `sad_store` is `None` —
    /// no panicking, no half-hydrated state, just a fresh builder with
    /// `requested_prefix` latched for the prefix-mismatch guard.
    #[tokio::test]
    async fn with_prefix_no_store_returns_empty_builder() {
        let prefix = test_digest(b"some-prefix");
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);

        let b = SadEventBuilder::with_prefix(None, None, Some(checker), &prefix)
            .await
            .expect("with_prefix(no store) succeeds with empty builder");

        assert!(b.sad_verification().is_none());
        assert!(b.pending_events().is_empty());
    }

    /// `walk_back_to_first_owner` rejects a forged event in the verified
    /// chain map (M1 audit finding from round 9). The walk consumes a
    /// SAID-keyed map; if the caller built the map from unverified data
    /// with mismatched `said`/content, the walk would route through the
    /// forgery to an arbitrary owner-stored event. The new repair flow
    /// always runs `SelVerifier::verify_page` (which calls
    /// `event.verify_said()` per event) over the fetched tail BEFORE
    /// constructing the chain map — this test verifies that
    /// pre-verification step catches the forgery.
    #[tokio::test]
    async fn forged_said_in_fetched_tail_rejected_by_verifier() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let v0 = SadEvent::icp(TEST_TOPIC, wp, Some(gp)).unwrap();
        let v1 = SadEvent::upd(&v0, test_digest(b"legit-content")).unwrap();

        // Forge an event: claim v1's SAID but lie about content. SAID-derived
        // structural integrity would catch this — verify_said recomputes
        // the SAID over the (blanked) content, which won't match v1.said.
        let mut forged = SadEvent::upd(&v0, test_digest(b"forged-content")).unwrap();
        forged.said = v1.said;
        // forged now has v1.said but content hashing produces a different SAID.

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        let err = verifier
            .verify_page(&[v0, forged])
            .await
            .expect_err("forged SAID must be rejected");
        assert!(
            err.to_string().contains("SAID")
                || err.to_string().contains("said")
                || matches!(err, KelsError::InvalidSaid(_)),
            "Expected SAID verification error, got: {err:?}"
        );
    }

    /// `repair` refuses with `ChainHasUnverifiedEvents` when owner's local
    /// `sad_verification.policy_satisfied()` is `false` — catches local store
    /// tampering or KEL-side anchor unreachability before consulting the
    /// server. This is gate (a) in the round-9 repair flow.
    ///
    /// Constructs a SelVerification with `policy_satisfied=false` directly
    /// (no PolicyChecker that returns false here — the constructor bypass
    /// keeps the test focused on the gate, not the upstream cause).
    #[tokio::test]
    async fn repair_refuses_when_owner_policy_unsatisfied() {
        use crate::store::InMemorySadStore;
        use crate::types::SadBranchTip;

        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let v0 = SadEvent::icp(TEST_TOPIC, wp, Some(gp)).unwrap();

        // Hand-build a SelVerification with `policy_satisfied = false`. This
        // simulates owner's local store reporting that some past event
        // failed its policy check (e.g., disk tampering re-derived a valid
        // SAID but the KEL anchor doesn't match the post-tamper SAID).
        let unsatisfied = SelVerification::new(
            vec![SadBranchTip {
                tip: v0.clone(),
                tracked_write_policy: wp,
                governance_policy: Some(gp),
                events_since_evaluation: 0,
                last_governance_version: None,
            }],
            false, // policy_satisfied = false (the gate)
            Some(0),
            None,
        );
        assert!(!unsatisfied.policy_satisfied());

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let store: Arc<dyn SadStore> = Arc::new(InMemorySadStore::new());
        // sad_client = None, but the gate fires before the client check, so
        // we never reach the OfflineMode branch.
        // Actually: gate fires after sad_client/checker/verification checks.
        // We need a sad_client too — but we can use None for an offline-mode
        // error to be raised first IF the gate fires later. To pin the
        // policy gate firing, we need all preconditions met. Since
        // SadStoreClient is concrete (no trait), and sad_client is required,
        // we work around by setting up a builder where the gate fires before
        // the network call. The current order is: sad_store check → sad_client
        // check → checker check → verification check → policy_satisfied check.
        // So we need sad_client to NOT be None. SadStoreClient::new takes a
        // URL string and doesn't connect synchronously; an unreachable URL is
        // fine because the policy gate fires before any HTTP call.
        let sad_client = crate::SadStoreClient::new("http://127.0.0.1:1").unwrap();
        let mut b = SadEventBuilder::new(Some(sad_client), Some(store), Some(checker));
        b.sad_verification = Some(unsatisfied);

        let err = b
            .repair(Some(test_digest(b"content")))
            .await
            .expect_err("repair must refuse on owner-local policy_satisfied=false");
        assert!(
            matches!(err, KelsError::ChainHasUnverifiedEvents(_)),
            "Expected ChainHasUnverifiedEvents, got: {err:?}"
        );
        assert!(
            b.pending_events().is_empty(),
            "no event should be staged when repair is refused at the gate"
        );
    }

    /// Resume round-trip: verify a chain from scratch, then resume from the
    /// resulting token and verify the same page of additional events. The
    /// final state must match what verifying the whole chain from inception
    /// would produce.
    #[tokio::test]
    async fn sel_verifier_resume_matches_from_scratch() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept_deterministic(TEST_TOPIC, wp, gp, None).unwrap();
        b.update(test_digest(b"c1")).unwrap();
        b.update(test_digest(b"c2")).unwrap();
        let checkpoint_pending = b.pending_events().to_vec();

        b.evaluate(None, None, None).unwrap();
        b.update(test_digest(b"c3")).unwrap();
        let full_pending = b.pending_events().to_vec();
        let prefix = *b.prefix().unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);

        // Verify first half, produce a token.
        let mut first = SelVerifier::new(Some(&prefix), Arc::clone(&checker));
        first.verify_page(&checkpoint_pending).await.unwrap();
        let token = first.finish().await.unwrap();

        // Resume from the token, verify the remainder.
        let remaining = &full_pending[checkpoint_pending.len()..];
        let mut resumed = SelVerifier::resume(&token, Arc::clone(&checker)).unwrap();
        resumed.verify_page(remaining).await.unwrap();
        let resumed_token = resumed.finish().await.unwrap();

        // Verify the whole chain from scratch and compare.
        let mut fresh = SelVerifier::new(Some(&prefix), Arc::clone(&checker));
        fresh.verify_page(&full_pending).await.unwrap();
        let fresh_token = fresh.finish().await.unwrap();

        assert_eq!(
            resumed_token.current_event().said,
            fresh_token.current_event().said
        );
        assert_eq!(
            resumed_token.current_event().version,
            fresh_token.current_event().version
        );
        assert_eq!(resumed_token.write_policy(), fresh_token.write_policy());
        assert_eq!(
            resumed_token.governance_policy(),
            fresh_token.governance_policy()
        );
        assert_eq!(
            resumed_token.events_since_evaluation(),
            fresh_token.events_since_evaluation()
        );
        assert_eq!(
            resumed_token.last_governance_version(),
            fresh_token.last_governance_version()
        );
        assert_eq!(
            resumed_token.establishment_version(),
            fresh_token.establishment_version()
        );
    }

    /// Hand-build a divergent `SelVerification` for use as a builder seed.
    /// Returns `(divergent_token, v0_event, v1_a, v1_b)` — callers needing to
    /// seed a `sad_store` for `repair` to walk back through use these events
    /// directly. Owner's branch is the SAID-sorted-first of `v1_a` / `v1_b`
    /// per the `branches().first()` convention.
    async fn build_divergent_token() -> (SelVerification, SadEvent, SadEvent, SadEvent) {
        use crate::types::SelVerifier;

        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let v0 = SadEvent::icp(TEST_TOPIC, wp, Some(gp)).unwrap();
        let v1_a = SadEvent::upd(&v0, test_digest(b"content_a")).unwrap();
        let v1_b = SadEvent::upd(&v0, test_digest(b"content_b")).unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier
            .verify_page(&[v0.clone(), v1_a.clone(), v1_b.clone()])
            .await
            .unwrap();
        let divergent = verifier.finish().await.unwrap();
        assert!(
            divergent.diverged_at_version().is_some(),
            "fixture invariant: hand-built chain must be divergent"
        );
        (divergent, v0, v1_a, v1_b)
    }

    /// `update` must refuse on a divergent chain — the owner's only legal
    /// next staging operation is `repair`. Mirrors the KEL `rec`/`cnt`
    /// recovery model where normal rotations stop until divergence is
    /// resolved.
    #[tokio::test]
    async fn update_refused_on_divergent_chain() {
        let (divergent, _v0, _v1_a, _v1_b) = build_divergent_token().await;
        let at = divergent.diverged_at_version().unwrap();

        let mut b = SadEventBuilder::new(None, None, None);
        b.sad_verification = Some(divergent);

        let err = b.update(test_digest(b"new-content")).unwrap_err();
        match err {
            KelsError::SelDivergent { at: reported } => assert_eq!(reported, at),
            other => panic!("Expected SelDivergent, got: {other:?}"),
        }
        // Pending must be unchanged — refusal is a no-op.
        assert!(b.pending_events.is_empty());
    }

    /// `evaluate` must refuse on a divergent chain for symmetry with `update`.
    /// A "pure evaluation" Evl on a divergent chain would pretend the
    /// divergence doesn't exist; resolving the fork is the only meaningful
    /// next step.
    #[tokio::test]
    async fn evaluate_refused_on_divergent_chain() {
        let (divergent, _v0, _v1_a, _v1_b) = build_divergent_token().await;
        let at = divergent.diverged_at_version().unwrap();

        let mut b = SadEventBuilder::new(None, None, None);
        b.sad_verification = Some(divergent);

        let err = b.evaluate(None, None, None).unwrap_err();
        match err {
            KelsError::SelDivergent { at: reported } => assert_eq!(reported, at),
            other => panic!("Expected SelDivergent, got: {other:?}"),
        }
        assert!(b.pending_events.is_empty());
    }

    // The `repair_allowed_on_divergent_chain` test from prior rounds is
    // superseded by `repair_at_divergence_version` above, which pins the
    // M1-followup contract: divergent repair stages an Rpr at the divergence
    // boundary, not at owner_tip+1. The old test only proved a Rpr was
    // staged; the new test pins the boundary semantics.

    /// Stamping is `or_else`: an existing `Some(_)` is preserved (the local
    /// verifier already saw the fork — server's report is redundant). When
    /// the local detection produced `None`, the server's reported version is
    /// stamped through.
    #[tokio::test]
    async fn set_diverged_at_version_or_else_semantics() {
        // Linear-chain token first: stamping should set the value.
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept_deterministic(TEST_TOPIC, wp, gp, None).unwrap();
        b.update(test_digest(b"c1")).unwrap();
        let prefix = *b.prefix().unwrap();
        let pending = b.pending_events().to_vec();
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&prefix), Arc::clone(&checker));
        verifier.verify_page(&pending).await.unwrap();
        let mut linear = verifier.finish().await.unwrap();
        assert_eq!(linear.diverged_at_version(), None);
        linear.set_diverged_at_version(7);
        assert_eq!(
            linear.diverged_at_version(),
            Some(7),
            "stamp must set on a token that didn't observe divergence"
        );

        // Already-divergent token: stamping with a different value is a no-op.
        let (mut divergent, _, _, _) = build_divergent_token().await;
        let original = divergent.diverged_at_version().unwrap();
        divergent.set_diverged_at_version(original + 100);
        assert_eq!(
            divergent.diverged_at_version(),
            Some(original),
            "stamp must NOT overwrite a previously observed divergence"
        );
    }
}
