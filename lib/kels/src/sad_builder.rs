//! SAD Event Log builder.
//!
//! Single-actor, protocol-agnostic construction surface for SAD Event Logs.
//! Round-12 shape: chains are identity-rooted, so every staging method that
//! produces a v1+ event must bind it to a specific IEL event via
//! `identity_event`. The builder fetches the IEL's current state from the
//! server on demand to find the binding.
//!
//! Per-method:
//! - `incept_chain(identity, topic, initial_content)` atomically stages
//!   `[Icp, Upd]` (the inception batch rule requires a v1 Upd alongside
//!   every Icp).
//! - `update(content)` stages a v+1 `Upd`; binds to the most recent IEL
//!   non-terminal event for the chain's identity.
//! - `seal()` stages a `Sea`; binds to the most recent IEL non-terminal
//!   event (governance carrier).
//! - `repair()` stages an `Rpr` resolving divergence; bundles pending into
//!   the batch.
//! - `contest()` / `decommission()` stage terminal events and bundle
//!   pending; `decommission` fails fast on divergent chains.
//! - `flush()` submits pending atomically and rolls into verified state.
//!
//! Cross-chain access: the builder uses `SadStoreClient` for all HTTP I/O.
//! When it needs to verify (its own chain or its IEL binding), it
//! constructs an [`AnchoredIelResolver`](crate::AnchoredIelResolver) on
//! demand from `sad_client.as_iel_source()` — no `IelResolver` field
//! lives on the builder; the durable handle is the client.
//!
//! Staging methods are synchronous (in-memory construction). Methods that
//! need IEL state (everything except plain getters) are `async` because
//! they hit the network. Only `flush()` and `publish_pending()` write.

use std::sync::Arc;

use crate::{
    AnchoredIelResolver, KelsError,
    client::SadStoreClient,
    store::SadStore,
    types::{
        IdentityEventKind, IelResolver, PolicyChecker, SadEvent, SadEventTerminalState,
        SelVerification, SelVerifier,
    },
};

/// Outcome of a successful `SadEventBuilder::flush`.
#[derive(Debug, Clone)]
#[must_use = "FlushOutcome carries divergence signals — check diverged_at_at_submit before continuing"]
pub struct FlushOutcome {
    pub diverged_at_at_submit: Option<u64>,
    pub applied: bool,
    /// `Some(_)` when the server skipped the batch because the chain is
    /// already terminal (gossip-race-already-contested / decommissioned).
    /// In that case `applied=false` and pending was NOT absorbed —
    /// callers must reconcile their local state against the server view.
    pub terminal: Option<SadEventTerminalState>,
}

/// Builder for SAD Event Logs.
///
/// Dual-state per `IdentityEventBuilder`: `sad_verification` holds the
/// verified tail (from server or local store), `pending_events` holds
/// locally staged events. The builder is non-generic over `KeyProvider` —
/// SAD events carry no signatures; authorization is via IEL bindings
/// resolved at the server's verifier.
pub struct SadEventBuilder {
    sad_client: Option<SadStoreClient>,
    sad_store: Option<Arc<dyn SadStore>>,
    /// Policy checker for hydration in `with_prefix`, for verifying IEL
    /// bindings during staging, and for absorbing pending in `flush`.
    /// `None` permits offline construction (tests, staging-only flows);
    /// `flush` errors when pending is non-empty and this is unset.
    checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
    sad_verification: Option<SelVerification>,
    pending_events: Vec<SadEvent>,
    /// Prefix the caller expects this builder to operate on (captured via
    /// `with_prefix`). Mismatch surfaces at flush via the verifier's
    /// prefix check.
    requested_prefix: Option<cesr::Digest256>,
}

impl SadEventBuilder {
    // ==================== Constructors ====================

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

    /// Construct a builder for an existing SE chain at `sel_prefix` and
    /// hydrate verified state from the **server**, via
    /// `sad_client.verify_sad_events`.
    ///
    /// Used by the stage-and-exit CLI lifecycle commands (`update`, `seal`,
    /// `repair`, `contest`, `decommission`) where each invocation is
    /// short-lived and there is no useful local SAD store. The pre-walk
    /// collects the chain's queried IEL SAIDs so the constructed
    /// `IelResolver` can answer `is_satisfied` during the SE walk; the
    /// SE verification itself is checker-gated, so the trust boundary
    /// matches `with_prefix` — the server's wire output is verified
    /// end-to-end before being adopted as the builder's tail. Returns a
    /// fresh builder with no `sad_verification` if the server has no
    /// events for the prefix.
    pub async fn with_remote_prefix(
        sad_client: SadStoreClient,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
        sel_prefix: &cesr::Digest256,
    ) -> Result<Self, KelsError> {
        let mut builder = Self::new(Some(sad_client.clone()), None, Some(Arc::clone(&checker)));
        builder.requested_prefix = Some(*sel_prefix);

        let source = sad_client.as_sad_source()?;
        let queried = match crate::collect_identity_event_saids(
            sel_prefix,
            &source,
            crate::page_size(),
            crate::max_pages(),
        )
        .await
        {
            Ok(s) => s,
            Err(KelsError::NotFound(_)) => return Ok(builder),
            Err(e) => return Err(e),
        };

        let resolver = builder.build_iel_resolver_from(&sad_client, &checker, queried)?;
        match sad_client
            .verify_sad_events(sel_prefix, Arc::clone(&checker), resolver)
            .await
        {
            Ok(v) => builder.sad_verification = Some(v),
            Err(KelsError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        Ok(builder)
    }

    /// Construct a builder for an existing SE chain at `sel_prefix` and
    /// hydrate verified state from the **local SAD store only**.
    ///
    /// Hydration runs only when both `sad_store` and `checker` are set —
    /// the round-12 verifier also needs an `IelResolver`, which the
    /// builder constructs from `sad_client`. Without `sad_client` the
    /// hydration path is skipped (the prefix-mismatch guard at flush
    /// catches misuse). `KelsError::NotFound` from the local walk is
    /// silently absorbed — the chain may not exist locally yet.
    pub async fn with_prefix(
        sad_client: Option<SadStoreClient>,
        sad_store: Option<Arc<dyn SadStore>>,
        checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
        sel_prefix: &cesr::Digest256,
    ) -> Result<Self, KelsError> {
        let mut builder = Self::new(sad_client.clone(), sad_store.clone(), checker.clone());
        builder.requested_prefix = Some(*sel_prefix);
        if let (Some(store), Some(c), Some(client)) =
            (sad_store.as_ref(), checker.as_ref(), sad_client.as_ref())
        {
            // SE pre-walk over the local store, accumulating only
            // identity_event SAIDs so the IelResolver can answer
            // is_satisfied during the verification walk that follows.
            let mut prewalk = crate::SadStorePageLoader::new(store.as_ref());
            let queried = match crate::collect_identity_event_saids_from_loader(
                &mut prewalk,
                sel_prefix,
                crate::page_size(),
                crate::max_pages(),
            )
            .await
            {
                Ok(s) => s,
                Err(KelsError::NotFound(_)) => std::collections::BTreeSet::new(),
                Err(e) => return Err(e),
            };
            let resolver = builder.build_iel_resolver_from(client, c, queried)?;
            let mut loader = crate::SadStorePageLoader::new(store.as_ref());
            match crate::sel_completed_verification(
                &mut loader,
                sel_prefix,
                Arc::clone(c),
                resolver,
                crate::page_size(),
                crate::max_pages(),
            )
            .await
            {
                Ok(v) => builder.sad_verification = Some(v),
                Err(KelsError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(builder)
    }

    // ==================== Accessors ====================

    pub fn pending_events(&self) -> &[SadEvent] {
        &self.pending_events
    }

    pub fn sad_verification(&self) -> Option<&SelVerification> {
        self.sad_verification.as_ref()
    }

    /// The most recent event on the chain (pending tail wins over verified
    /// tip). `None` on a fresh, un-incepted builder.
    pub fn last_event(&self) -> Option<&SadEvent> {
        if let Some(last) = self.pending_events.last() {
            return Some(last);
        }
        self.sad_verification.as_ref().map(|v| v.current_event())
    }

    pub fn last_said(&self) -> Option<&cesr::Digest256> {
        self.last_event().map(|e| &e.said)
    }

    /// SE prefix (pending v0, then verified prefix).
    pub fn prefix(&self) -> Option<&cesr::Digest256> {
        if let Some(first) = self.pending_events.first() {
            return Some(&first.prefix);
        }
        self.sad_verification.as_ref().map(|v| v.prefix())
    }

    pub fn version(&self) -> Option<u64> {
        self.last_event().map(|e| e.version)
    }

    /// True iff the chain has terminated locally (a `Cnt` or `Dec` is
    /// staged or already verified). Refuses further staging.
    pub fn is_terminal(&self) -> bool {
        if self.pending_events.iter().any(|e| e.kind.is_terminal()) {
            return true;
        }
        self.sad_verification
            .as_ref()
            .map(|v| v.is_contested() || v.is_decommissioned())
            .unwrap_or(false)
    }

    /// Number of non-evaluation events on the current branch since the
    /// last governance evaluation, or since chain start if none. Walks
    /// pending events forward from the verified counter (if any).
    pub fn events_since_evaluation(&self) -> usize {
        let mut count = self
            .sad_verification
            .as_ref()
            .map(|v| v.events_since_evaluation())
            .unwrap_or(0);
        for event in &self.pending_events {
            // `Icp` and any governance-evaluating kind reset the counter;
            // everything else (only `Upd` in practice) increments. Folded
            // into one arm to satisfy `clippy::if_same_then_else`.
            if event.kind == crate::types::SadEventKind::Icp || event.kind.evaluates_governance() {
                count = 0;
            } else {
                count += 1;
            }
        }
        count
    }

    pub fn needs_evaluation(&self) -> bool {
        self.events_since_evaluation() >= crate::MAX_NON_EVALUATION_EVENTS
    }

    // ==================== Staging (async) ====================

    /// Atomically stage `[Icp, Upd]` for a fresh SE chain bound to
    /// `identity`. Returns `(icp_said, upd_said)`.
    ///
    /// The Upd's `identity_event` resolves to the most recent IEL
    /// non-terminal event for `identity` (Icp or Evl). The IEL must be
    /// locally reachable via `sad_client`.
    pub async fn incept_chain(
        &mut self,
        identity: cesr::Digest256,
        topic: impl Into<String>,
        initial_content: cesr::Digest256,
    ) -> Result<(cesr::Digest256, cesr::Digest256), KelsError> {
        self.require_fresh_builder()?;

        let topic_str: String = topic.into();
        let icp = SadEvent::icp(identity, topic_str)?;

        if let Some(expected) = self.requested_prefix
            && icp.prefix != expected
        {
            return Err(KelsError::InvalidKel(format!(
                "Icp prefix {} does not match requested prefix {}",
                icp.prefix, expected
            )));
        }

        let iel_event_said = self.fetch_current_iel_binding(&identity).await?;
        let upd = SadEvent::upd(&icp, iel_event_said, initial_content)?;

        let icp_said = icp.said;
        let upd_said = upd.said;
        self.pending_events.push(icp);
        self.pending_events.push(upd);
        Ok((icp_said, upd_said))
    }

    /// Stage a v+1 `Upd` carrying new content. Resolves `identity_event`
    /// from the most recent IEL non-terminal event for the chain's
    /// identity at staging time.
    pub async fn update(&mut self, content: cesr::Digest256) -> Result<cesr::Digest256, KelsError> {
        self.require_incepted()?;
        self.require_non_terminal()?;
        self.require_non_divergent()?;

        if self.needs_evaluation() {
            return Err(KelsError::EvaluationRequired);
        }

        let identity = self.chain_identity()?;
        let iel_event_said = self.fetch_current_iel_binding(&identity).await?;
        let tip = self.current_tip()?.clone();
        let upd = SadEvent::upd(&tip, iel_event_said, content)?;
        let said = upd.said;
        self.pending_events.push(upd);
        Ok(said)
    }

    /// Stage a `Sea` (degenerate seal marker). Carries `previous.content`
    /// forward. `identity_event` binds to the most recent IEL non-terminal
    /// event (governance carrier) for the chain's identity.
    pub async fn seal(&mut self) -> Result<cesr::Digest256, KelsError> {
        self.require_incepted()?;
        self.require_non_terminal()?;
        self.require_non_divergent()?;

        let identity = self.chain_identity()?;
        let iel_event_said = self.fetch_current_iel_binding(&identity).await?;
        let tip = self.current_tip()?.clone();
        let sea = SadEvent::sea(&tip, iel_event_said)?;
        let said = sea.said;
        self.pending_events.push(sea);
        Ok(said)
    }

    /// Stage an `Rpr` (repair) at the truncation boundary so the
    /// server-side `is_repair` path heals divergence (or
    /// adversary-extended linear). Pre-flight runs
    /// `verify_server_chain_pre_action` (full client-side re-verify of
    /// the server's view).
    pub async fn repair(&mut self) -> Result<cesr::Digest256, KelsError> {
        self.require_incepted()?;
        self.require_non_terminal()?;

        let server_view = self
            .verify_server_chain_pre_action()
            .await?
            .ok_or_else(|| {
                KelsError::OfflineMode("repair requires sad_client + checker for pre-flight".into())
            })?;

        if !server_view.policy_satisfied() {
            return Err(KelsError::ChainHasUnverifiedEvents(
                "server-fetched chain reports policy_satisfied=false — \
                 will not repair against unverified data"
                    .into(),
            ));
        }

        let owner_verification = self
            .sad_verification
            .as_ref()
            .ok_or(KelsError::NotIncepted)?;
        if !owner_verification.policy_satisfied() {
            return Err(KelsError::ChainHasUnverifiedEvents(
                "owner-local sad_verification reports policy_satisfied=false — \
                 local store may have been tampered, or KEL anchors are \
                 unreachable; resolve before repairing"
                    .into(),
            ));
        }

        // Boundary derivation. Mirrors the round-10 logic but uses
        // round-12 accessors.
        let owner_tip = owner_verification.current_event().clone();
        let prefix = owner_tip.prefix;
        let boundary_version = match server_view.diverged_at_version() {
            Some(d) => {
                if d == 0 {
                    return Err(KelsError::InvalidKel(
                        "server reports divergence at v0 — cannot repair below \
                         inception"
                            .into(),
                    ));
                }
                d - 1
            }
            None => {
                let server_tip_v = server_view.current_event().version;
                if server_tip_v <= owner_tip.version {
                    return Err(KelsError::NothingToRepair);
                }
                owner_tip.version
            }
        };

        // Fetch boundary event from owner's local store.
        let sad_store = self
            .sad_store
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("repair requires a sad_store".into()))?;
        let (boundary_events, _has_more) = sad_store
            .load_sel_events(&prefix, 1, boundary_version)
            .await?;
        let boundary = boundary_events.into_iter().next().ok_or_else(|| {
            KelsError::InvalidKel(format!(
                "boundary event at version {} not in local store for prefix {} \
                 — owner-local view may be incomplete",
                boundary_version, prefix
            ))
        })?;
        if boundary.version != boundary_version {
            return Err(KelsError::InvalidKel(format!(
                "local store offset {} returned event at version {} (prefix {}) \
                 — index ordering is inconsistent",
                boundary_version, boundary.version, prefix
            )));
        }

        let identity = self.chain_identity()?;
        let iel_event_said = self.fetch_current_iel_binding(&identity).await?;
        let rpr = SadEvent::rpr(&boundary, iel_event_said)?;
        let said = rpr.said;
        self.pending_events.push(rpr);
        Ok(said)
    }

    /// Stage a `Cnt` (and any pending events) for submission.
    ///
    /// On a linear chain with pending, `Cnt` extends the last pending
    /// event. On a linear chain without pending, `Cnt` extends the
    /// verified tip. On a divergent chain (no pending), `Cnt` extends
    /// the **lower-SAID branch tip** for cross-node determinism (mirrors
    /// IEL's lower-SAID rule at `docs/design/iel/event-log.md:174`).
    ///
    /// Pre-flight: full client-side server-chain re-verification via
    /// `verify_server_chain_pre_action`. Defense-in-depth.
    ///
    /// No local divergent-state pre-flight (deliberate asymmetry with
    /// `decommission`): `Cnt` is a valid resolver on sealed-divergent
    /// chains; the builder lets the server route.
    pub async fn contest(&mut self) -> Result<cesr::Digest256, KelsError> {
        self.require_incepted()?;
        self.require_non_terminal()?;

        // server_view intentionally discarded: contest is valid on every
        // non-terminal state (linear, sealed, divergent-sealed) — a
        // builder-side fail-fast would block legitimate use. The handler
        // delivers the precise terminal-state error if anything's amiss.
        let _server_view = self.verify_server_chain_pre_action().await?;

        let cnt_previous = self.choose_terminal_anchor(false)?;
        let identity = self.chain_identity()?;
        let iel_event_said = self.fetch_current_iel_binding(&identity).await?;
        let cnt = SadEvent::cnt(&cnt_previous, iel_event_said)?;
        let said = cnt.said;
        self.pending_events.push(cnt);
        Ok(said)
    }

    /// Stage a `Dec` (and any pending events) for submission.
    ///
    /// Fails fast on a divergent chain — `Dec` cannot resolve a divergent
    /// SE chain (sealed-divergent → ContestRequired; unsealed-divergent →
    /// RepairRequired). The builder surfaces
    /// `KelsError::DecommissionBlockedByDivergence` and lets the operator
    /// route to `repair()` or `contest()`. The error is generic by design
    /// — it doesn't distinguish sealed vs. unsealed locally; the
    /// operator's next move comes from the server's response if they
    /// force-submit.
    pub async fn decommission(&mut self) -> Result<cesr::Digest256, KelsError> {
        self.require_incepted()?;
        self.require_non_terminal()?;

        let server_view = self.verify_server_chain_pre_action().await?;

        if self.is_divergent_view(server_view.as_ref()) {
            return Err(KelsError::DecommissionBlockedByDivergence(
                "chain is divergent — use contest() (sealed) or repair() (unsealed) instead".into(),
            ));
        }

        let dec_previous = self.choose_terminal_anchor(true)?;
        let identity = self.chain_identity()?;
        let iel_event_said = self.fetch_current_iel_binding(&identity).await?;
        let dec = SadEvent::dec(&dec_previous, iel_event_said)?;
        let said = dec.said;
        self.pending_events.push(dec);
        Ok(said)
    }

    // ==================== Submission (async) ====================

    /// Publish staged events as generic SAD objects in the object store.
    /// Idempotent (object store keys by SAID). Does not promote events
    /// into the SEL — `flush()` does that.
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
    /// Three phases (mirrors round-10 / IEL flush):
    /// 1. `sad_client.submit_sad_events(...)` — server commits.
    /// 2. `sad_store.store_sel_event` per event — local cache write-through.
    /// 3. `absorb_pending` — re-verify against server-accepted state.
    ///
    /// Special case: a flush that includes an `Rpr` triggers a fresh
    /// owner-local rehydrate (the Rpr's `previous` points at a
    /// pre-truncation event that isn't a current branch tip; resume +
    /// verify_page would error). After server's `is_repair` truncation
    /// the chain is linear from v0 to the Rpr; rehydrate from the local
    /// SAD store.
    pub async fn flush(&mut self) -> Result<FlushOutcome, KelsError> {
        if self.pending_events.is_empty() {
            return Ok(FlushOutcome {
                diverged_at_at_submit: None,
                applied: false,
                terminal: None,
            });
        }

        let client = self
            .sad_client
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("flush requires a SadStoreClient".into()))?;
        if self.checker.is_none() {
            return Err(KelsError::OfflineMode(
                "flush requires a PolicyChecker".into(),
            ));
        }

        let response = client.submit_sad_events(&self.pending_events).await?;

        // Terminal-state skip: server reports the chain is already
        // contested / decommissioned. No events landed; do NOT write
        // through to the local store, do NOT absorb pending. Surface
        // the signal so the caller can reconcile.
        if let Some(terminal) = response.terminal {
            return Ok(FlushOutcome {
                diverged_at_at_submit: response.diverged_at,
                applied: response.applied,
                terminal: Some(terminal),
            });
        }

        if let Some(store) = self.sad_store.as_ref() {
            for event in &self.pending_events {
                store.store_sel_event(event).await?;
            }
        }

        let was_repair = self.pending_events.iter().any(|e| e.kind.is_repair());

        if was_repair {
            #[allow(clippy::expect_used)]
            let prefix = *self
                .prefix()
                .expect("repair flush has prefix from pending or verification");
            #[allow(clippy::expect_used)]
            let checker = Arc::clone(
                self.checker
                    .as_ref()
                    .expect("flush is_none-checked checker above"),
            );
            #[allow(clippy::expect_used)]
            let store = self
                .sad_store
                .as_ref()
                .expect("repair flush requires sad_store (validated by repair pre-flight)");
            // Pre-walk the local store post-repair to collect identity_event
            // SAIDs the IelResolver needs to query during the rehydrate
            // verification.
            let mut prewalk = crate::SadStorePageLoader::new(store.as_ref());
            let queried = crate::collect_identity_event_saids_from_loader(
                &mut prewalk,
                &prefix,
                crate::page_size(),
                crate::max_pages(),
            )
            .await?;
            let resolver = self.build_iel_resolver(queried)?;
            let mut loader = crate::SadStorePageLoader::new(store.as_ref());
            let fresh = crate::sel_completed_verification(
                &mut loader,
                &prefix,
                checker,
                resolver,
                crate::page_size(),
                crate::max_pages(),
            )
            .await?;
            self.sad_verification = Some(fresh);
            self.pending_events.clear();
        } else {
            self.absorb_pending().await?;

            if let Some(at) = response.diverged_at
                && let Some(v) = self.sad_verification.as_mut()
            {
                v.set_diverged_at_version(at);
            }
        }

        Ok(FlushOutcome {
            diverged_at_at_submit: response.diverged_at,
            applied: response.applied,
            terminal: None,
        })
    }

    // ==================== Private helpers ====================

    /// Construct an `IelResolver` from this builder's `sad_client` and
    /// `checker`, with the caller-provided queried_saids forwarded to the
    /// resolver. Errors if `sad_client` or `checker` is missing. Used
    /// per-verify-call — the `iel_client` (= `sad_client`) is the durable
    /// handle; the resolver is ephemeral.
    fn build_iel_resolver(
        &self,
        queried_saids: impl IntoIterator<Item = cesr::Digest256>,
    ) -> Result<Arc<dyn IelResolver + Send + Sync>, KelsError> {
        let client = self.sad_client.as_ref().ok_or_else(|| {
            KelsError::OfflineMode("IelResolver construction requires a SadStoreClient".into())
        })?;
        let checker = self.checker.as_ref().ok_or_else(|| {
            KelsError::OfflineMode("IelResolver construction requires a PolicyChecker".into())
        })?;
        self.build_iel_resolver_from(client, checker, queried_saids)
    }

    fn build_iel_resolver_from(
        &self,
        client: &SadStoreClient,
        checker: &Arc<dyn PolicyChecker + Send + Sync>,
        queried_saids: impl IntoIterator<Item = cesr::Digest256>,
    ) -> Result<Arc<dyn IelResolver + Send + Sync>, KelsError> {
        let source: Arc<dyn crate::types::PagedIelSource + Send + Sync> =
            Arc::new(client.as_iel_source()?);
        Ok(Arc::new(
            AnchoredIelResolver::new(
                source,
                Arc::clone(checker),
                crate::page_size(),
                crate::max_pages(),
            )
            .with_queried_saids(queried_saids),
        ))
    }

    /// Verify the server's view of the chain. Returns `None` if any of
    /// `sad_client` / `checker` / `prefix` is missing (offline-staging
    /// flows). Mirrors `IdentityEventBuilder::verify_server_chain_pre_action`.
    ///
    /// Round-12 third follow-up: pre-walks the server's SE chain to collect
    /// the unique `identity_event` SAIDs the IEL verification needs to query.
    /// The collected set is forwarded to the `IelResolver` via
    /// `with_queried_saids` so `is_satisfied` answers correctly during the
    /// SE chain walk.
    async fn verify_server_chain_pre_action(&self) -> Result<Option<SelVerification>, KelsError> {
        let (Some(client), Some(checker), Some(prefix)) = (
            self.sad_client.as_ref(),
            self.checker.as_ref(),
            self.prefix(),
        ) else {
            return Ok(None);
        };

        // SE pre-walk over the server's SE source — streaming, accumulates
        // only SAIDs.
        let queried_iel_saids = crate::collect_identity_event_saids(
            prefix,
            &client.as_sad_source()?,
            crate::page_size(),
            crate::max_pages(),
        )
        .await?;

        let resolver = self.build_iel_resolver_from(client, checker, queried_iel_saids)?;
        Ok(Some(
            client
                .verify_sad_events(prefix, Arc::clone(checker), resolver)
                .await?,
        ))
    }

    /// Fetch the SAID of the most recent IEL non-terminal event (Icp or
    /// Evl) for `identity`. The event's policy fields authorize SE
    /// staging. Errors if the IEL is divergent (no canonical "current"
    /// event) or terminated (chain can't authorize new SE work).
    async fn fetch_current_iel_binding(
        &self,
        identity: &cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError> {
        let client = self.sad_client.as_ref().ok_or_else(|| {
            KelsError::OfflineMode("fetch_current_iel_binding requires a SadStoreClient".into())
        })?;
        let checker = self.checker.as_ref().ok_or_else(|| {
            KelsError::OfflineMode("fetch_current_iel_binding requires a PolicyChecker".into())
        })?;
        let verification = client
            .verify_identity_events(identity, Arc::clone(checker))
            .await?;
        if verification.is_divergent() {
            return Err(KelsError::IelDivergent(format!(
                "IEL {} is divergent — cannot pick a binding for SE staging",
                identity
            )));
        }
        if verification.is_contested() || verification.is_decommissioned() {
            return Err(KelsError::InvalidIel(format!(
                "IEL {} is terminal (contested/decommissioned) — cannot \
                 authorize SE staging",
                identity
            )));
        }
        let current = verification.current_event().ok_or_else(|| {
            KelsError::InvalidIel(format!(
                "IEL {} has no current event (unexpected on a non-divergent chain)",
                identity
            ))
        })?;
        // Round-12 SE bindings target Icp / Evl events (the kinds that
        // carry policy state forward). Terminal IEL kinds (Cnt / Dec)
        // shouldn't be reachable here because we just gated on
        // `is_contested` / `is_decommissioned`, but stay defensive.
        if matches!(
            current.kind,
            IdentityEventKind::Cnt | IdentityEventKind::Dec
        ) {
            return Err(KelsError::InvalidIel(format!(
                "IEL {}'s current event is terminal kind {} — cannot bind SE \
                 events to a terminated IEL",
                identity, current.kind
            )));
        }
        Ok(current.said)
    }

    /// Choose the event a terminal staging op (`Cnt` or `Dec`) should
    /// extend. Pending tail wins. Otherwise: linear → verified tip;
    /// divergent (Cnt only — Dec already gated out) → lower-SAID branch
    /// tip from the verification token.
    fn choose_terminal_anchor(&self, decommission: bool) -> Result<SadEvent, KelsError> {
        if let Some(last) = self.pending_events.last() {
            return Ok(last.clone());
        }
        let view = self
            .sad_verification
            .as_ref()
            .ok_or(KelsError::NotIncepted)?;
        if let Some(_at) = view.diverged_at_version() {
            if decommission {
                // Should be unreachable — `decommission` already returned
                // `DecommissionBlockedByDivergence` before reaching here.
                return Err(KelsError::DecommissionBlockedByDivergence(
                    "chain is divergent (defense-in-depth: should have been caught upstream)"
                        .into(),
                ));
            }
            // Lower-SAID branch tip: `branches` is sorted ascending by
            // tip SAID at `SelVerifier::finish`, so the first entry is
            // the lower-SAID one.
            let branch = view.branches().first().ok_or_else(|| {
                KelsError::InvalidKel("verification has no branches — impossible per finish".into())
            })?;
            return Ok(branch.tip.clone());
        }
        Ok(view.current_event().clone())
    }

    /// `chain.identity` — the IEL prefix this SE chain is bound to.
    /// Sourced from the verified Icp (preferred) or the pending v0 Icp.
    fn chain_identity(&self) -> Result<cesr::Digest256, KelsError> {
        if let Some(v) = self.sad_verification.as_ref() {
            // The Icp's `identity` is preserved per-branch on
            // `SadBranchTip.identity` — all branches share it.
            #[allow(clippy::expect_used)]
            let branch = v
                .branches()
                .first()
                .expect("SelVerification invariant: branches non-empty");
            return Ok(branch.identity);
        }
        let icp = self
            .pending_events
            .iter()
            .find(|e| e.kind == crate::types::SadEventKind::Icp)
            .ok_or(KelsError::NotIncepted)?;
        icp.identity.ok_or_else(|| {
            KelsError::InvalidKel("pending Icp missing identity field — invariant breach".into())
        })
    }

    fn require_fresh_builder(&self) -> Result<(), KelsError> {
        if !self.pending_events.is_empty() || self.sad_verification.is_some() {
            return Err(KelsError::InvalidKel(
                "Inception requires an empty builder (no pending or verified state)".into(),
            ));
        }
        Ok(())
    }

    fn require_incepted(&self) -> Result<(), KelsError> {
        if self.sad_verification.is_some() || !self.pending_events.is_empty() {
            return Ok(());
        }
        Err(KelsError::NotIncepted)
    }

    fn require_non_divergent(&self) -> Result<(), KelsError> {
        if let Some(v) = self.sad_verification.as_ref()
            && let Some(at) = v.diverged_at_version()
        {
            return Err(KelsError::SelDivergent { at });
        }
        Ok(())
    }

    fn require_non_terminal(&self) -> Result<(), KelsError> {
        if self.is_terminal() {
            return Err(KelsError::InvalidKel(
                "chain has already terminated (Cnt or Dec) — no further events accepted".into(),
            ));
        }
        Ok(())
    }

    fn current_tip(&self) -> Result<&SadEvent, KelsError> {
        self.last_event().ok_or(KelsError::NotIncepted)
    }

    fn is_divergent_view(&self, server_view: Option<&SelVerification>) -> bool {
        if let Some(v) = server_view
            && v.diverged_at_version().is_some()
        {
            return true;
        }
        self.sad_verification
            .as_ref()
            .map(|v| v.diverged_at_version().is_some())
            .unwrap_or(false)
    }

    /// Re-verify pending events against server-accepted state and roll
    /// into `sad_verification`, then clear pending. Mirrors IEL's
    /// `absorb_pending`.
    async fn absorb_pending(&mut self) -> Result<(), KelsError> {
        if self.pending_events.is_empty() {
            return Ok(());
        }
        let checker = self
            .checker
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("flush requires a PolicyChecker".into()))?
            .clone();
        // queried_saids = prior token's queried (carried across resume) ∪
        // identity_event SAIDs from the pending events being absorbed.
        // SE pre-walk for absorb_pending is in-memory: pending_events is
        // already a `Vec<SadEvent>` held by the builder, so SAID extraction
        // is a single pass with no I/O.
        let mut queried: std::collections::BTreeSet<cesr::Digest256> = self
            .sad_verification
            .as_ref()
            .map(|v| v.queried_saids().clone())
            .unwrap_or_default();
        for ev in &self.pending_events {
            if let Some(s) = ev.identity_event {
                queried.insert(s);
            }
        }
        let resolver = self.build_iel_resolver(queried)?;

        let mut verifier = if let Some(ref v) = self.sad_verification {
            SelVerifier::resume(v, Arc::clone(&checker), Arc::clone(&resolver))?
        } else {
            SelVerifier::new(
                self.requested_prefix.as_ref(),
                Arc::clone(&checker),
                Arc::clone(&resolver),
            )
        };

        verifier.verify_page(&self.pending_events).await?;
        self.sad_verification = Some(verifier.finish().await?);
        self.pending_events.clear();
        Ok(())
    }
}
