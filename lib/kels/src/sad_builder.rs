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

use std::sync::Arc;

use crate::{
    KelsError, MAX_NON_EVALUATION_EVENTS,
    client::SadStoreClient,
    store::SadStore,
    types::{PolicyChecker, SadEvent, SadEventKind, SelVerification, SelVerifier},
};

/// Outcome of a successful `SadEventBuilder::flush` — carries forward signals
/// from the server response that the local verifier could not have observed.
///
/// Forward-extensible: future flush signals (e.g., per-event acceptance
/// breakdown, server-side rate-limit headroom) get added as additional fields
/// without rebreaking the call sites.
#[derive(Debug, Clone)]
#[must_use = "FlushOutcome carries divergence signals — check diverged_at_at_submit before continuing to stage events"]
pub struct FlushOutcome {
    /// Server-reported divergence version, if a fork was created or
    /// already-existed at submit time. `None` means the chain is linear
    /// according to the server. The same value is also stamped onto
    /// `sad_verification().diverged_at_version()` so subsequent stagers can
    /// gate on builder state alone.
    pub diverged_at_at_submit: Option<u64>,
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

    /// Construct a builder for an existing SEL at `sel_prefix` and attempt
    /// to hydrate verified state from the server.
    ///
    /// This is the resume-from-existing-chain constructor — call `new` instead
    /// for inception flows. Use this when you know which chain you intend to
    /// operate on and want the builder pre-populated with the server-accepted
    /// tail. `sad_store` is a write-through cache on flush success; it is not
    /// used for hydration to avoid a second set of invariants.
    ///
    /// Hydration is attempted only when both `sad_client` and `checker` are
    /// provided. With either missing the builder still latches `sel_prefix`
    /// as `requested_prefix` and skips the round-trip; a later
    /// `incept`/`incept_deterministic` that derives a different prefix will
    /// be rejected at `flush` time via the verifier's prefix check — closes
    /// the silent-state-drift footgun where a caller asked for chain X and
    /// accidentally initialized chain Y.
    ///
    /// `KelsError::NotFound` from the server is silently absorbed: the chain
    /// may not exist yet (it's about to be incepted at this prefix), and the
    /// prefix-mismatch guard above remains armed via `requested_prefix`.
    pub async fn with_prefix(
        sad_client: Option<SadStoreClient>,
        sad_store: Option<Arc<dyn SadStore>>,
        checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
        sel_prefix: &cesr::Digest256,
    ) -> Result<Self, KelsError> {
        let mut builder = Self::new(sad_client.clone(), sad_store, checker.clone());
        builder.requested_prefix = Some(*sel_prefix);
        if let (Some(client), Some(c)) = (sad_client.as_ref(), checker.as_ref()) {
            match client.verify_sad_events(sel_prefix, Arc::clone(c)).await {
                Ok(v) => builder.sad_verification = Some(v),
                // Chain not yet inducted — caller may be about to incept it.
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

    /// Stage an `Rpr`. Serves as the evaluation proof at `from_version`.
    /// For actually-divergent chains, repair requires branch-tip information
    /// the verification token does not carry — callers in that case must
    /// construct the repair event out of band.
    pub fn repair(
        &mut self,
        content: Option<cesr::Digest256>,
    ) -> Result<cesr::Digest256, KelsError> {
        self.require_established()?;

        let event = SadEvent::rpr(self.current_tip()?, content)?;
        let said = event.said;
        self.pending_events.push(event);
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
    /// **Always retry on error rather than discarding pending.** All three
    /// phases are idempotent: `submit_sad_events` deduplicates by SAID,
    /// `sad_store.store` overwrites under the same key, and
    /// `absorb_pending` re-verifies from current server state. A retry
    /// after a phase-1 failure resubmits cleanly; a retry after a phase-2
    /// or phase-3 failure no-ops on the server side and converges the
    /// builder's local view.
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
        // state. If absorb_pending later fails, the cache is fine: it holds
        // events that any subsequent with_prefix() will re-verify via the
        // server.
        if let Some(store) = self.sad_store.as_ref() {
            for event in &self.pending_events {
                let value = serde_json::to_value(event)?;
                store.store(&event.said, &value).await?;
            }
        }

        self.absorb_pending().await?;

        // Stamp the server-reported divergence onto the local token. The local
        // verifier only saw the owner's batch, so its `diverged_at_version`
        // would be `None` even when the server has two branches at this
        // version. This is record-keeping, not recovery — the owner calls
        // `repair` themselves when they're ready, exactly as they'd call
        // `rec`/`cnt` on a divergent KEL today.
        if let Some(at) = response.diverged_at
            && let Some(v) = self.sad_verification.as_mut()
        {
            v.set_diverged_at_version(at);
        }

        Ok(FlushOutcome {
            diverged_at_at_submit: response.diverged_at,
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
    use crate::types::SadEvent;

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

    #[test]
    fn repair_stages_rpr_from_tip() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept(TEST_TOPIC, wp, gp).unwrap();
        b.update(test_digest(b"c1")).unwrap();

        let rpr_said = b.repair(Some(test_digest(b"repaired"))).unwrap();
        let rpr = b
            .pending_events()
            .last()
            .expect("at least one pending event");
        assert_eq!(rpr.said, rpr_said);
        assert_eq!(rpr.kind, SadEventKind::Rpr);
        assert_eq!(rpr.version, 2);
        assert!(rpr.write_policy.is_none());
        assert!(rpr.governance_policy.is_none());
    }

    #[test]
    fn incept_deterministic_without_establish_content_ok() {
        // Content on Est is optional — omitting it still produces a valid chain.
        let mut b = SadEventBuilder::new(None, None, None);
        b.incept_deterministic(TEST_TOPIC, test_digest(b"wp"), test_digest(b"gp"), None)
            .unwrap();
        assert_eq!(b.pending_events().len(), 2);
        assert!(b.pending_events()[1].content.is_none());
    }

    /// Happy path: incept_deterministic → update → evaluate → update → repair,
    /// verified end-to-end against a fresh `SelVerifier` to confirm every
    /// staged event is structurally sound and correctly chained.
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
        b.repair(Some(test_digest(b"c5"))).unwrap();

        let prefix = *b.prefix().unwrap();
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&prefix), Arc::clone(&checker));
        verifier
            .verify_page(b.pending_events())
            .await
            .expect("staged chain verifies");
        let verification = verifier.finish().await.expect("verification finishes");
        assert_eq!(verification.current_event().version, 5);
        assert_eq!(verification.current_event().kind, SadEventKind::Rpr);
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

    /// A builder whose cached `sad_verification` came from a divergent chain
    /// must surface `CannotResumeDivergentChain` when `absorb_pending` fires.
    /// Integration-level guard for `flush`: `flush` calls `submit_sad_events`
    /// → `sad_store.store` → `absorb_pending`, and `absorb_pending` is where
    /// the verifier resume happens. Exercising it directly proves the error
    /// propagates without needing a live server in the unit harness.
    #[tokio::test]
    async fn absorb_pending_errors_on_divergent_cached_verification() {
        use crate::types::SelVerifier;

        // Hand-build a divergent chain: v0 Icp (with governance) → two v1 Upd
        // extending the same tip. Verify it to get a SelVerification that
        // carries `diverged_at_version = Some(1)`.
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let v0 = SadEvent::icp(TEST_TOPIC, wp, Some(gp)).unwrap();
        let v1_a = SadEvent::upd(&v0, test_digest(b"content_a")).unwrap();
        let v1_b = SadEvent::upd(&v0, test_digest(b"content_b")).unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier
            .verify_page(&[v0.clone(), v1_a.clone(), v1_b])
            .await
            .unwrap();
        let divergent = verifier.finish().await.unwrap();
        assert!(divergent.diverged_at_version().is_some());

        // Seed a builder with the divergent token and queue a pending event so
        // absorb_pending's early-return-on-empty doesn't short-circuit. The
        // checker stored on the builder is what absorb_pending hands to
        // SelVerifier::resume.
        let mut b = SadEventBuilder::new(None, None, Some(Arc::clone(&checker)));
        b.sad_verification = Some(divergent);

        let pending = SadEvent::upd(&v1_a, test_digest(b"content_a2")).unwrap();
        b.pending_events.push(pending);

        let err = b.absorb_pending().await.unwrap_err();
        assert!(
            matches!(err, KelsError::CannotResumeDivergentChain),
            "Expected CannotResumeDivergentChain, got: {err:?}"
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
    /// Mirrors the construction in `absorb_pending_errors_on_divergent_cached_verification`
    /// but factored so the divergence-gating tests below can reuse it.
    /// Returns `(divergent_token, v0_event)` — `v0` is the inception, useful
    /// when the test wants to stage a `repair` from the established branch.
    async fn build_divergent_token() -> (SelVerification, SadEvent) {
        use crate::types::SelVerifier;

        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let v0 = SadEvent::icp(TEST_TOPIC, wp, Some(gp)).unwrap();
        let v1_a = SadEvent::upd(&v0, test_digest(b"content_a")).unwrap();
        let v1_b = SadEvent::upd(&v0, test_digest(b"content_b")).unwrap();

        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = SelVerifier::new(Some(&v0.prefix), Arc::clone(&checker));
        verifier
            .verify_page(&[v0.clone(), v1_a, v1_b])
            .await
            .unwrap();
        let divergent = verifier.finish().await.unwrap();
        assert!(
            divergent.diverged_at_version().is_some(),
            "fixture invariant: hand-built chain must be divergent"
        );
        (divergent, v0)
    }

    /// `update` must refuse on a divergent chain — the owner's only legal
    /// next staging operation is `repair`. Mirrors the KEL `rec`/`cnt`
    /// recovery model where normal rotations stop until divergence is
    /// resolved.
    #[tokio::test]
    async fn update_refused_on_divergent_chain() {
        let (divergent, _v0) = build_divergent_token().await;
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
        let (divergent, _v0) = build_divergent_token().await;
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

    /// `repair` must succeed on a divergent chain — it's the explicit
    /// owner-initiated recovery path. Without this, a builder seeded with a
    /// divergent token would have no escape route within the builder API.
    #[tokio::test]
    async fn repair_allowed_on_divergent_chain() {
        let (divergent, _v0) = build_divergent_token().await;

        let mut b = SadEventBuilder::new(None, None, None);
        b.sad_verification = Some(divergent);

        let rpr_said = b
            .repair(Some(test_digest(b"repaired-content")))
            .expect("repair must succeed on divergent chain");

        assert_eq!(b.pending_events.len(), 1);
        let staged = b.pending_events.last().unwrap();
        assert_eq!(staged.said, rpr_said);
        assert_eq!(staged.kind, SadEventKind::Rpr);
    }

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
        let (mut divergent, _) = build_divergent_token().await;
        let original = divergent.diverged_at_version().unwrap();
        divergent.set_diverged_at_version(original + 100);
        assert_eq!(
            divergent.diverged_at_version(),
            Some(original),
            "stamp must NOT overwrite a previously observed divergence"
        );
    }
}
