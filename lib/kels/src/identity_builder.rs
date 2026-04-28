//! Identity Event Log builder.
//!
//! Single-actor, protocol-agnostic construction surface for Identity Event
//! Logs. Mirrors `SadEventBuilder` for the IEL primitive: manages chain
//! state, enforces per-kind field rules, and flushes pending events to the
//! server. Does **not** anchor — anchoring is the caller's job (the same
//! shape as `SadEventBuilder`).
//!
//! Per-method:
//! - `incept(auth_policy, governance_policy, topic)` stages a v0 `Icp`.
//! - `evolve(auth?, gov?)` stages a v+1 `Evl` extending the current tip
//!   (or the last pending event); refuses on divergent chains.
//! - `contest()` builds a `Cnt` and bundles pending into the batch. On a
//!   divergent chain (no pending), it deterministically extends the
//!   lower-SAID branch tip to avoid different builders on different nodes
//!   producing different `Cnt` events.
//! - `decommission()` builds a `Dec` and bundles pending. Fails fast on
//!   divergent chains — only `Cnt` resolves a divergent IEL.
//! - `flush()` submits pending atomically; rehydrates verification on
//!   terminal-event flushes.
//!
//! Staging methods are synchronous (in-memory construction + validation).
//! Only `flush()` hits the network.

use std::sync::Arc;

use crate::{
    KelsError,
    client::SadStoreClient,
    store::IdentityStore,
    types::{
        IdentityEvent, IelVerification, IelVerifier, PolicyChecker, SubmitIdentityEventsResponse,
    },
};

/// Outcome of a successful `IdentityEventBuilder::flush`.
#[derive(Debug, Clone)]
#[must_use = "FlushIdentityOutcome carries divergence and applied signals — check before continuing"]
pub struct FlushIdentityOutcome {
    /// Server-reported divergence version, if a fork was created or
    /// already-existed at submit time.
    pub diverged_at_at_submit: Option<u64>,
    /// `true` iff the submit committed at least one new event server-side.
    pub applied: bool,
}

/// Builder for Identity Event Logs.
///
/// Dual-state per `SadEventBuilder`: `iel_verification` holds the verified
/// tail (from server or local store), `pending_events` holds locally staged
/// events. The builder is non-generic over `KeyProvider` — IEL events carry
/// no signatures; authorization is via KEL anchoring.
pub struct IdentityEventBuilder {
    sad_client: Option<SadStoreClient>,
    iel_store: Option<Arc<dyn IdentityStore>>,
    /// Policy checker used for hydration in `with_prefix` and for flush
    /// re-verification. `None` permits offline construction (tests,
    /// staging-only flows); `flush` errors when pending is non-empty and
    /// this is unset.
    checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
    iel_verification: Option<IelVerification>,
    pending_events: Vec<IdentityEvent>,
    /// Prefix the caller expects this builder to operate on (captured via
    /// `with_prefix`). Carried into the verifier at flush time so a later
    /// `incept` producing a different prefix surfaces as a structural error.
    requested_prefix: Option<cesr::Digest256>,
}

impl IdentityEventBuilder {
    // ==================== Constructors ====================

    pub fn new(
        sad_client: Option<SadStoreClient>,
        iel_store: Option<Arc<dyn IdentityStore>>,
        checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
    ) -> Self {
        Self {
            sad_client,
            iel_store,
            checker,
            iel_verification: None,
            pending_events: Vec::new(),
            requested_prefix: None,
        }
    }

    /// Construct a builder for an existing IEL at `iel_prefix` and hydrate
    /// owner-local verified state from the **local IEL store only**.
    ///
    /// Mirrors `SadEventBuilder::with_prefix` for the IEL primitive. Server
    /// state is consulted on-demand at action time (`contest`,
    /// `decommission`, `flush`); never at construction.
    pub async fn with_prefix(
        sad_client: Option<SadStoreClient>,
        iel_store: Option<Arc<dyn IdentityStore>>,
        checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
        iel_prefix: &cesr::Digest256,
    ) -> Result<Self, KelsError> {
        let mut builder = Self::new(sad_client, iel_store.clone(), checker.clone());
        builder.requested_prefix = Some(*iel_prefix);
        if let (Some(store), Some(c)) = (iel_store.as_ref(), checker.as_ref()) {
            let mut loader = crate::IdentityStorePageLoader::new(store.as_ref());
            match crate::iel_completed_verification(
                &mut loader,
                iel_prefix,
                Arc::clone(c),
                crate::page_size(),
                crate::max_pages(),
            )
            .await
            {
                Ok(v) => builder.iel_verification = Some(v),
                Err(KelsError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(builder)
    }

    // ==================== Accessors ====================

    pub fn pending_events(&self) -> &[IdentityEvent] {
        &self.pending_events
    }

    pub fn iel_verification(&self) -> Option<&IelVerification> {
        self.iel_verification.as_ref()
    }

    /// Most recent event (pending tail, then verified tip). `None` on a
    /// fresh builder.
    pub fn last_event(&self) -> Option<&IdentityEvent> {
        if let Some(last) = self.pending_events.last() {
            return Some(last);
        }
        self.iel_verification
            .as_ref()
            .and_then(|v| v.current_event())
    }

    /// IEL prefix (pending v0, then verified prefix).
    pub fn prefix(&self) -> Option<&cesr::Digest256> {
        if let Some(first) = self.pending_events.first() {
            return Some(&first.prefix);
        }
        self.iel_verification.as_ref().map(|v| v.prefix())
    }

    // ==================== Staging (sync) ====================

    /// Stage a v0 `Icp` declaring both `auth_policy` and `governance_policy`.
    pub fn incept(
        &mut self,
        auth_policy: cesr::Digest256,
        governance_policy: cesr::Digest256,
        topic: impl Into<String>,
    ) -> Result<cesr::Digest256, KelsError> {
        self.require_fresh_builder()?;

        let event = IdentityEvent::icp(auth_policy, governance_policy, topic)?;
        let said = event.said;

        if let Some(expected) = self.requested_prefix
            && event.prefix != expected
        {
            return Err(KelsError::InvalidIel(format!(
                "Icp prefix {} does not match requested prefix {}",
                event.prefix, expected
            )));
        }

        self.pending_events.push(event);
        Ok(said)
    }

    /// Stage a v+1 `Evl` extending the current tip (or last pending event).
    /// `auth_policy` / `governance_policy` carry forward when `None`.
    pub fn evolve(
        &mut self,
        auth_policy: Option<cesr::Digest256>,
        governance_policy: Option<cesr::Digest256>,
    ) -> Result<cesr::Digest256, KelsError> {
        self.require_incepted()?;
        self.require_non_divergent()?;
        self.require_non_terminal()?;

        let event = IdentityEvent::evl(self.current_tip()?, auth_policy, governance_policy)?;
        let said = event.said;
        self.pending_events.push(event);
        Ok(said)
    }

    /// Stage a `Cnt` (and any pending events) for submission.
    ///
    /// On a linear chain with pending events, `Cnt` extends the last pending
    /// event. On a linear chain without pending, `Cnt` extends the verified
    /// tip. On a divergent chain (no pending — `evolve` refuses on divergent),
    /// `Cnt` extends the **lower-SAID branch tip** for cross-node determinism.
    ///
    /// Pre-flight: full client-side server-chain re-verification via
    /// `verify_server_chain_pre_action`. Defense-in-depth: a buggy server
    /// would otherwise be taken at its word when the builder picks a tip.
    pub async fn contest(&mut self) -> Result<cesr::Digest256, KelsError> {
        self.require_incepted()?;
        self.require_non_terminal()?;

        let server_view = self.verify_server_chain_pre_action().await?;

        let cnt_previous = self.choose_terminal_anchor(server_view.as_ref(), false)?;
        let cnt = IdentityEvent::cnt(&cnt_previous)?;
        let said = cnt.said;
        self.pending_events.push(cnt);
        Ok(said)
    }

    /// Stage a `Dec` (and any pending events) for submission.
    ///
    /// Fails fast on a divergent chain — only `Cnt` resolves a divergent IEL
    /// (the merge handler would reject `Dec` with `ContestRequired`; the
    /// builder surfaces the same intent locally).
    pub async fn decommission(&mut self) -> Result<cesr::Digest256, KelsError> {
        self.require_incepted()?;
        self.require_non_terminal()?;

        let server_view = self.verify_server_chain_pre_action().await?;

        if self.is_divergent(server_view.as_ref()) {
            return Err(KelsError::contest_required_iel(
                "decommission rejected: chain is divergent — use contest() instead",
            ));
        }

        let dec_previous = self.choose_terminal_anchor(server_view.as_ref(), true)?;
        let dec = IdentityEvent::dec(&dec_previous)?;
        let said = dec.said;
        self.pending_events.push(dec);
        Ok(said)
    }

    // ==================== Submission (async) ====================

    /// Submit pending events to the IEL server, then absorb into verified
    /// state. Mirrors `SadEventBuilder::flush`.
    pub async fn flush(&mut self) -> Result<FlushIdentityOutcome, KelsError> {
        if self.pending_events.is_empty() {
            return Ok(FlushIdentityOutcome {
                diverged_at_at_submit: None,
                applied: false,
            });
        }

        let client = self
            .sad_client
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("flush requires a SadStoreClient".into()))?;
        let response: SubmitIdentityEventsResponse =
            client.submit_identity_events(&self.pending_events).await?;

        // Local cache write-through.
        if let Some(store) = self.iel_store.as_ref() {
            for event in &self.pending_events {
                store.store_iel_event(event).await?;
            }
        }

        // Absorb pending into the verified state. Unlike SE, IEL has no Rpr
        // and no archival — terminal events (`Cnt` / `Dec`) just extend the
        // chain. The verifier's resume + verify_page path correctly sets
        // `is_contested` / `is_decommissioned` via flush_generation, so no
        // special terminal rehydrate is needed.
        self.absorb_pending().await?;

        if let Some(at) = response.diverged_at
            && let Some(v) = self.iel_verification.as_mut()
        {
            v.set_diverged_at_version(at);
        }

        Ok(FlushIdentityOutcome {
            diverged_at_at_submit: response.diverged_at,
            applied: response.applied,
        })
    }

    /// Verify the server's view of the chain, returning the verification
    /// token. `None` when no `sad_client` is configured (offline staging).
    /// Used by `contest` / `decommission` as a defense-in-depth pre-flight.
    async fn verify_server_chain_pre_action(&self) -> Result<Option<IelVerification>, KelsError> {
        let (Some(client), Some(checker), Some(prefix)) = (
            self.sad_client.as_ref(),
            self.checker.as_ref(),
            self.prefix(),
        ) else {
            return Ok(None);
        };
        Ok(Some(
            client
                .verify_identity_events(prefix, Arc::clone(checker))
                .await?,
        ))
    }

    /// Re-verify pending events against the local verifier and roll into
    /// `iel_verification`, then clear pending. Mirrors SE's `absorb_pending`.
    async fn absorb_pending(&mut self) -> Result<(), KelsError> {
        if self.pending_events.is_empty() {
            return Ok(());
        }
        let checker = self
            .checker
            .as_ref()
            .ok_or_else(|| {
                KelsError::OfflineMode(
                    "absorb_pending requires a PolicyChecker — set one at builder construction"
                        .into(),
                )
            })?
            .clone();

        let mut verifier = match self.iel_verification.as_ref() {
            Some(v) => IelVerifier::resume(v, checker)?,
            None => {
                #[allow(clippy::expect_used)]
                let prefix = self
                    .pending_events
                    .first()
                    .map(|e| e.prefix)
                    .expect("pending non-empty per the early-return above");
                IelVerifier::new(Some(&prefix), checker)
            }
        };

        verifier.verify_page(&self.pending_events).await?;
        self.iel_verification = Some(verifier.finish().await?);
        self.pending_events.clear();
        Ok(())
    }

    // ==================== Private helpers ====================

    fn require_fresh_builder(&self) -> Result<(), KelsError> {
        if !self.pending_events.is_empty() || self.iel_verification.is_some() {
            return Err(KelsError::InvalidIel(
                "Inception requires an empty builder (no pending or verified state)".into(),
            ));
        }
        Ok(())
    }

    fn require_incepted(&self) -> Result<(), KelsError> {
        if self.iel_verification.is_some() || !self.pending_events.is_empty() {
            return Ok(());
        }
        Err(KelsError::NotIncepted)
    }

    fn require_non_divergent(&self) -> Result<(), KelsError> {
        if let Some(v) = self.iel_verification.as_ref()
            && let Some(at) = v.diverged_at_version()
        {
            return Err(KelsError::IelDivergent(format!(
                "diverged at version {}",
                at
            )));
        }
        Ok(())
    }

    fn require_non_terminal(&self) -> Result<(), KelsError> {
        let already_terminal = self
            .iel_verification
            .as_ref()
            .map(|v| v.is_contested() || v.is_decommissioned())
            .unwrap_or(false)
            || self.pending_events.iter().any(|e| e.kind.is_terminal());
        if already_terminal {
            return Err(KelsError::InvalidIel(
                "chain has already terminated (Cnt or Dec) — no further events accepted".into(),
            ));
        }
        Ok(())
    }

    fn current_tip(&self) -> Result<&IdentityEvent, KelsError> {
        if let Some(last) = self.pending_events.last() {
            return Ok(last);
        }
        let v = self
            .iel_verification
            .as_ref()
            .ok_or(KelsError::NotIncepted)?;
        v.current_event()
            .ok_or_else(|| KelsError::IelDivergent("no single tip on a divergent chain".into()))
    }

    fn is_divergent(&self, server_view: Option<&IelVerification>) -> bool {
        if let Some(v) = server_view
            && v.is_divergent()
        {
            return true;
        }
        self.iel_verification
            .as_ref()
            .map(|v| v.is_divergent())
            .unwrap_or(false)
    }

    /// Choose the event that the next terminal event (`Cnt` or `Dec`) should
    /// extend. Linear: pending tail or verified tip. Divergent (Cnt only):
    /// lower-SAID branch tip from the server view (preferred) or local view.
    fn choose_terminal_anchor(
        &self,
        server_view: Option<&IelVerification>,
        decommission: bool,
    ) -> Result<IdentityEvent, KelsError> {
        if let Some(last) = self.pending_events.last() {
            return Ok(last.clone());
        }

        let view = server_view
            .or(self.iel_verification.as_ref())
            .ok_or(KelsError::NotIncepted)?;

        if view.is_divergent() {
            if decommission {
                return Err(KelsError::contest_required_iel(
                    "decommission rejected: chain is divergent — use contest() instead",
                ));
            }
            // Lower-SAID branch tip (deterministic across nodes). `branches`
            // is sorted ascending by tip SAID at `IelVerifier::finish`, so
            // the first entry is the lower-SAID one.
            let branch = view.branches().first().ok_or_else(|| {
                KelsError::InvalidIel("verification has no branches — impossible per finish".into())
            })?;
            return Ok(branch.tip.clone());
        }

        view.current_event()
            .cloned()
            .ok_or_else(|| KelsError::InvalidIel("non-divergent chain has no current event".into()))
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::IdentityEventKind;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    const TEST_TOPIC: &str = "kels/iel/v1/identity/test";

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

    #[test]
    fn incept_stages_v0_with_correct_fields() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        b.incept(auth, gov, TEST_TOPIC).unwrap();

        assert_eq!(b.pending_events().len(), 1);
        let v0 = &b.pending_events()[0];
        assert_eq!(v0.kind, IdentityEventKind::Icp);
        assert_eq!(v0.version, 0);
        assert_eq!(v0.auth_policy, auth);
        assert_eq!(v0.governance_policy, gov);
    }

    #[test]
    fn incept_rejects_when_pending_nonempty() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        b.incept(test_digest(b"auth"), test_digest(b"gov"), TEST_TOPIC)
            .unwrap();
        assert!(matches!(
            b.incept(test_digest(b"auth"), test_digest(b"gov"), TEST_TOPIC),
            Err(KelsError::InvalidIel(_))
        ));
    }

    #[test]
    fn evolve_extends_pending_tail() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        b.incept(auth, gov, TEST_TOPIC).unwrap();

        b.evolve(None, None).unwrap();
        assert_eq!(b.pending_events().len(), 2);
        let v1 = &b.pending_events()[1];
        assert_eq!(v1.kind, IdentityEventKind::Evl);
        assert_eq!(v1.version, 1);
        assert_eq!(v1.auth_policy, auth);
        assert_eq!(v1.governance_policy, gov);
    }

    #[test]
    fn evolve_with_new_auth_policy_evolves() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        let auth1 = test_digest(b"auth-1");
        let auth2 = test_digest(b"auth-2");
        let gov = test_digest(b"gov");
        b.incept(auth1, gov, TEST_TOPIC).unwrap();
        b.evolve(Some(auth2), None).unwrap();

        let v1 = &b.pending_events()[1];
        assert_eq!(v1.auth_policy, auth2);
        assert_eq!(v1.governance_policy, gov);
    }

    #[test]
    fn evolve_before_incept_fails() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        assert!(matches!(b.evolve(None, None), Err(KelsError::NotIncepted)));
    }

    #[tokio::test]
    async fn flush_offline_returns_offline_error() {
        let mut b = IdentityEventBuilder::new(
            None,
            None,
            Some(Arc::new(AlwaysPassChecker) as Arc<dyn PolicyChecker + Send + Sync>),
        );
        b.incept(test_digest(b"auth"), test_digest(b"gov"), TEST_TOPIC)
            .unwrap();
        let err = b.flush().await.expect_err("flush requires SadStoreClient");
        assert!(matches!(err, KelsError::OfflineMode(_)));
    }

    #[tokio::test]
    async fn flush_empty_pending_no_op() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        let outcome = b.flush().await.unwrap();
        assert!(!outcome.applied);
        assert!(outcome.diverged_at_at_submit.is_none());
    }

    #[tokio::test]
    async fn contest_offline_fails_without_client() {
        // Without a sad_client, the pre-flight chain re-verification skips,
        // and contest() falls back to the local verification token. Without
        // a verification token (fresh builder + no incept), we expect
        // NotIncepted.
        let mut b = IdentityEventBuilder::new(None, None, None);
        let err = b.contest().await.expect_err("expected NotIncepted");
        assert!(matches!(err, KelsError::NotIncepted));
    }

    #[tokio::test]
    async fn contest_with_pending_extends_pending_tail() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        let auth = test_digest(b"auth");
        let gov = test_digest(b"gov");
        b.incept(auth, gov, TEST_TOPIC).unwrap();
        b.evolve(None, None).unwrap();

        let cnt_said = b.contest().await.unwrap();
        let staged = b.pending_events();
        assert_eq!(staged.len(), 3);
        let cnt = staged.last().unwrap();
        assert_eq!(cnt.kind, IdentityEventKind::Cnt);
        assert_eq!(cnt.said, cnt_said);
        assert_eq!(cnt.previous, Some(staged[1].said));
        assert_eq!(cnt.version, 2);
        // Cnt preserves both policies.
        assert_eq!(cnt.auth_policy, auth);
        assert_eq!(cnt.governance_policy, gov);
    }

    #[tokio::test]
    async fn decommission_with_pending_extends_pending_tail() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        let auth = test_digest(b"auth");
        let gov = test_digest(b"gov");
        b.incept(auth, gov, TEST_TOPIC).unwrap();
        b.evolve(None, None).unwrap();

        let dec_said = b.decommission().await.unwrap();
        let staged = b.pending_events();
        let dec = staged.last().unwrap();
        assert_eq!(dec.kind, IdentityEventKind::Dec);
        assert_eq!(dec.said, dec_said);
        assert_eq!(dec.previous, Some(staged[1].said));
        assert_eq!(dec.version, 2);
    }

    #[tokio::test]
    async fn evolve_after_terminal_in_pending_rejected() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        b.incept(test_digest(b"auth"), test_digest(b"gov"), TEST_TOPIC)
            .unwrap();
        b.evolve(None, None).unwrap();
        b.contest().await.unwrap();

        let err = b
            .evolve(None, None)
            .expect_err("expected terminal-state rejection");
        assert!(matches!(err, KelsError::InvalidIel(_)));
    }

    #[tokio::test]
    async fn decommission_after_contest_in_pending_rejected() {
        let mut b = IdentityEventBuilder::new(None, None, None);
        b.incept(test_digest(b"auth"), test_digest(b"gov"), TEST_TOPIC)
            .unwrap();
        b.contest().await.unwrap();

        let err = b
            .decommission()
            .await
            .expect_err("expected terminal-state rejection");
        assert!(matches!(err, KelsError::InvalidIel(_)));
    }

    /// Build an `IelVerification` for a divergent chain at v=1 by running the
    /// real `IelVerifier` over `[v0, v1_a, v1_b]` (any order — the verifier
    /// sorts branches by tip SAID at `finish`, which is the load-bearing
    /// invariant `choose_terminal_anchor` relies on). Returns the verification
    /// plus the lower-SAID branch tip for the assertion.
    async fn divergent_v1_verification(
        events: &[IdentityEvent],
        v1_a_said: cesr::Digest256,
        v1_b_said: cesr::Digest256,
    ) -> (IelVerification, cesr::Digest256) {
        let prefix = events[0].prefix;
        let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
        let mut verifier = IelVerifier::new(Some(&prefix), checker);
        verifier.verify_page(events).await.unwrap();
        let verification = verifier.finish().await.unwrap();
        assert!(
            verification.is_divergent(),
            "fixture must produce a divergent chain"
        );
        let lower = std::cmp::min(v1_a_said, v1_b_said);
        (verification, lower)
    }

    /// `contest()` on a divergent chain MUST extend the lower-SAID branch tip
    /// — the rule is load-bearing for federation convergence on contested
    /// state (`docs/design/iel/event-log.md` §"Choosing a branch tip"). Without
    /// it, two builders running on different nodes could stage `Cnt` events
    /// against different branches and split-brain on the contested state.
    #[tokio::test]
    async fn contest_on_divergent_chain_extends_lower_said_branch() {
        let auth_a = test_digest(b"auth-1");
        let auth_b = test_digest(b"auth-2");
        let gov = test_digest(b"gov");
        let v0 = IdentityEvent::icp(auth_a, gov, TEST_TOPIC).unwrap();
        let v1_a = IdentityEvent::evl(&v0, None, None).unwrap();
        let v1_b = IdentityEvent::evl(&v0, Some(auth_b), None).unwrap();

        let (verification, lower_said) = divergent_v1_verification(
            &[v0, v1_a.clone(), v1_b.clone()],
            v1_a.said,
            v1_b.said,
        )
        .await;

        let mut b = IdentityEventBuilder::new(None, None, None);
        b.iel_verification = Some(verification);

        let cnt_said = b.contest().await.unwrap();
        let cnt = b.pending_events().last().unwrap();
        assert_eq!(cnt.kind, IdentityEventKind::Cnt);
        assert_eq!(cnt.said, cnt_said);
        assert_eq!(cnt.version, 2);
        assert_eq!(
            cnt.previous,
            Some(lower_said),
            "Cnt must extend the lower-SAID branch tip on a divergent chain"
        );
    }

    /// Paired with `contest_on_divergent_chain_extends_lower_said_branch`:
    /// feeds the same divergent generation to the verifier in reversed order.
    /// `IelVerifier::finish` sorts branches by tip SAID, so the choice must be
    /// invariant under input-vec order — pins that the rule is about SAID
    /// ordering, not "first event seen wins".
    #[tokio::test]
    async fn contest_on_divergent_chain_lower_said_invariant_to_input_order() {
        let auth_a = test_digest(b"auth-1");
        let auth_b = test_digest(b"auth-2");
        let gov = test_digest(b"gov");
        let v0 = IdentityEvent::icp(auth_a, gov, TEST_TOPIC).unwrap();
        let v1_a = IdentityEvent::evl(&v0, None, None).unwrap();
        let v1_b = IdentityEvent::evl(&v0, Some(auth_b), None).unwrap();

        // Reversed order: v1_b before v1_a.
        let (verification, lower_said) = divergent_v1_verification(
            &[v0, v1_b.clone(), v1_a.clone()],
            v1_a.said,
            v1_b.said,
        )
        .await;

        let mut b = IdentityEventBuilder::new(None, None, None);
        b.iel_verification = Some(verification);

        b.contest().await.unwrap();
        let cnt = b.pending_events().last().unwrap();
        assert_eq!(
            cnt.previous,
            Some(lower_said),
            "Cnt previous must be lower SAID regardless of input order"
        );
    }
}
