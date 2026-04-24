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

use verifiable_storage::Chained;

use crate::{
    KelsError, MAX_NON_EVALUATION_EVENTS,
    client::SadStoreClient,
    store::SadStore,
    types::{PolicyChecker, SadEvent, SadEventKind, SelVerification, SelVerifier},
};

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
    sad_verification: Option<SelVerification>,
    pending_events: Vec<SadEvent>,
}

impl SadEventBuilder {
    // ==================== Constructors ====================

    /// Construct a bare builder. `sad_client` may be `None` for offline
    /// construction (tests, staging-only flows); `flush()` and
    /// `publish_pending()` require it.
    pub fn new(sad_client: Option<SadStoreClient>) -> Self {
        Self {
            sad_client,
            sad_store: None,
            sad_verification: None,
            pending_events: Vec::new(),
        }
    }

    /// Construct a builder and optionally hydrate existing SEL state.
    ///
    /// Hydration is attempted only when both `sad_client` and `sel_prefix` are
    /// provided — verification goes through the server via `verify_sad_events`,
    /// so the resulting state matches what any other caller would see.
    /// `sad_store` is a write-through cache on flush success; it is not used
    /// for hydration to avoid a second set of invariants.
    pub async fn with_dependencies(
        sad_client: Option<SadStoreClient>,
        sad_store: Option<Arc<dyn SadStore>>,
        sel_prefix: Option<&cesr::Digest256>,
        checker: &(dyn PolicyChecker + Sync),
    ) -> Result<Self, KelsError> {
        let sad_verification = match (&sad_client, sel_prefix) {
            (Some(client), Some(prefix)) => match client.verify_sad_events(prefix, checker).await {
                Ok(v) => Some(v),
                // A missing chain is legitimate — the caller may be about to
                // incept one at this prefix. Any other error propagates.
                Err(KelsError::NotFound(_)) => None,
                Err(e) => return Err(e),
            },
            _ => None,
        };

        Ok(Self {
            sad_client,
            sad_store,
            sad_verification,
            pending_events: Vec::new(),
        })
    }

    // ==================== Accessors ====================

    pub fn pending_events(&self) -> &[SadEvent] {
        &self.pending_events
    }

    pub fn sad_verification(&self) -> Option<&SelVerification> {
        self.sad_verification.as_ref()
    }

    pub fn last_event(&self) -> Option<&SadEvent> {
        if let Some(last) = self.pending_events.last() {
            return Some(last);
        }
        self.sad_verification.as_ref().map(|v| v.current_event())
    }

    pub fn last_said(&self) -> Option<&cesr::Digest256> {
        self.last_event().map(|e| &e.said)
    }

    pub fn prefix(&self) -> Option<&cesr::Digest256> {
        if let Some(first) = self.pending_events.first() {
            return Some(&first.prefix);
        }
        self.sad_verification.as_ref().map(|v| v.prefix())
    }

    pub fn version(&self) -> Option<u64> {
        self.last_event().map(|e| e.version)
    }

    /// The most recently declared or evolved `governance_policy` on the chain,
    /// preferring pending staged events over verified state.
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
    pub fn needs_evaluation(&self) -> bool {
        self.events_since_evaluation() >= MAX_NON_EVALUATION_EVENTS
    }

    // ==================== Staging (sync) ====================

    /// Stage a v0 `Icp` that declares both `write_policy` and `governance_policy`.
    ///
    /// Consumers of a chain inepted this way cannot recompute the prefix from
    /// `(topic, write_policy)` alone — the v0 SAID depends on
    /// `governance_policy` too. Use `incept_deterministic` when prefix-by-recomputation
    /// (exchange keys, identity chains, anything lookup-driven) is required.
    pub fn incept(
        &mut self,
        topic: &str,
        write_policy: cesr::Digest256,
        governance_policy: cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError> {
        self.require_fresh_builder()?;

        let event = SadEvent::create(
            topic.to_string(),
            SadEventKind::Icp,
            None,
            None,
            Some(write_policy),
            Some(governance_policy),
        )?;
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
        topic: &str,
        write_policy: cesr::Digest256,
        governance_policy: cesr::Digest256,
        content: Option<cesr::Digest256>,
    ) -> Result<(cesr::Digest256, cesr::Digest256), KelsError> {
        self.require_fresh_builder()?;

        let v0 = SadEvent::create(
            topic.to_string(),
            SadEventKind::Icp,
            None,
            None,
            Some(write_policy),
            None,
        )?;

        let mut v1 = v0.clone();
        v1.content = content;
        v1.kind = SadEventKind::Est;
        v1.write_policy = None;
        v1.governance_policy = Some(governance_policy);
        v1.increment()?;
        // Catch structural issues (e.g., topic / version constraints) before
        // we mutate state — either both stage or neither.
        v1.validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;

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
    /// crossed — caller must stage an `Evl` or `Rpr` first.
    pub fn update(&mut self, content: cesr::Digest256) -> Result<cesr::Digest256, KelsError> {
        self.require_established()?;

        if self.needs_evaluation() {
            return Err(KelsError::EvaluationRequired);
        }

        let tip = self.current_tip()?;
        let mut event = tip.clone();
        event.content = Some(content);
        event.kind = SadEventKind::Upd;
        event.write_policy = None;
        event.governance_policy = None;
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;

        let said = event.said;
        self.pending_events.push(event);
        Ok(said)
    }

    /// Stage an `Evl`. All three fields are optional — all-None is a legal
    /// pure evaluation that preserves current-pointer semantics.
    pub fn evaluate(
        &mut self,
        content: Option<cesr::Digest256>,
        write_policy: Option<cesr::Digest256>,
        governance_policy: Option<cesr::Digest256>,
    ) -> Result<cesr::Digest256, KelsError> {
        self.require_established()?;

        let tip = self.current_tip()?;
        let mut event = tip.clone();
        event.content = content;
        event.kind = SadEventKind::Evl;
        event.write_policy = write_policy;
        event.governance_policy = governance_policy;
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;

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

        let tip = self.current_tip()?;
        let mut event = tip.clone();
        event.content = content;
        event.kind = SadEventKind::Rpr;
        event.write_policy = None;
        event.governance_policy = None;
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;

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
    /// `sad_verification` via `SelVerifier::resume` + `verify_page` + `finish`.
    /// On failure, leaves `pending_events` intact so the caller can reason
    /// about already-anchored SAIDs.
    pub async fn flush(&mut self, checker: &(dyn PolicyChecker + Sync)) -> Result<(), KelsError> {
        if self.pending_events.is_empty() {
            return Ok(());
        }

        let client = self
            .sad_client
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("flush requires a SadStoreClient".into()))?;

        client.submit_sad_events(&self.pending_events).await?;

        // Persist before absorbing so local store never falls behind verified state.
        if let Some(store) = self.sad_store.as_ref() {
            for event in &self.pending_events {
                let value = serde_json::to_value(event)?;
                store.store(&event.said, &value).await?;
            }
        }

        self.absorb_pending(checker).await?;
        Ok(())
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

    fn current_tip(&self) -> Result<&SadEvent, KelsError> {
        self.last_event().ok_or(KelsError::NotIncepted)
    }

    /// Fold pending events into verified state via `SelVerifier::resume`.
    async fn absorb_pending(
        &mut self,
        checker: &(dyn PolicyChecker + Sync),
    ) -> Result<(), KelsError> {
        if self.pending_events.is_empty() {
            return Ok(());
        }

        let prefix = *self
            .prefix()
            .ok_or_else(|| KelsError::InvalidKel("No prefix for absorb".into()))?;

        let mut verifier = if let Some(ref v) = self.sad_verification {
            SelVerifier::resume(&prefix, v, checker)?
        } else {
            SelVerifier::new(&prefix, checker)
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
        let mut b = SadEventBuilder::new(None);
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
        let mut b = SadEventBuilder::new(None);
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

    #[test]
    fn second_inception_rejected() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None);
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
        let mut b = SadEventBuilder::new(None);
        let err = b.update(test_digest(b"c")).unwrap_err();
        assert!(matches!(err, KelsError::InvalidKel(_)));
    }

    #[test]
    fn update_after_incept_deterministic_chains_correctly() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None);
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
        let mut b = SadEventBuilder::new(None);
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
        let mut b = SadEventBuilder::new(None);
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
        let mut b = SadEventBuilder::new(None);
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
        let mut b = SadEventBuilder::new(None);
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
        let mut b = SadEventBuilder::new(None);
        b.incept_deterministic(TEST_TOPIC, wp, gp, Some(test_digest(b"c1")))
            .unwrap();
        b.update(test_digest(b"c2")).unwrap();
        b.evaluate(Some(test_digest(b"c3")), None, None).unwrap();
        b.update(test_digest(b"c4")).unwrap();
        b.repair(Some(test_digest(b"c5"))).unwrap();

        let prefix = *b.prefix().unwrap();
        let checker = AlwaysPassChecker;
        let mut verifier = SelVerifier::new(&prefix, &checker);
        verifier
            .verify_page(b.pending_events())
            .await
            .expect("staged chain verifies");
        let verification = verifier.finish().await.expect("verification finishes");
        assert_eq!(verification.current_event().version, 5);
        assert_eq!(verification.current_event().kind, SadEventKind::Rpr);
    }

    /// Resume round-trip: verify a chain from scratch, then resume from the
    /// resulting token and verify the same page of additional events. The
    /// final state must match what verifying the whole chain from inception
    /// would produce.
    #[tokio::test]
    async fn sel_verifier_resume_matches_from_scratch() {
        let wp = test_digest(b"wp");
        let gp = test_digest(b"gp");
        let mut b = SadEventBuilder::new(None);
        b.incept_deterministic(TEST_TOPIC, wp, gp, None).unwrap();
        b.update(test_digest(b"c1")).unwrap();
        b.update(test_digest(b"c2")).unwrap();
        let checkpoint_pending = b.pending_events().to_vec();

        b.evaluate(None, None, None).unwrap();
        b.update(test_digest(b"c3")).unwrap();
        let full_pending = b.pending_events().to_vec();
        let prefix = *b.prefix().unwrap();

        let checker = AlwaysPassChecker;

        // Verify first half, produce a token.
        let mut first = SelVerifier::new(&prefix, &checker);
        first.verify_page(&checkpoint_pending).await.unwrap();
        let token = first.finish().await.unwrap();

        // Resume from the token, verify the remainder.
        let remaining = &full_pending[checkpoint_pending.len()..];
        let mut resumed = SelVerifier::resume(&prefix, &token, &checker).unwrap();
        resumed.verify_page(remaining).await.unwrap();
        let resumed_token = resumed.finish().await.unwrap();

        // Verify the whole chain from scratch and compare.
        let mut fresh = SelVerifier::new(&prefix, &checker);
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
}
