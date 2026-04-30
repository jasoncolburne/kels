//! SAD Event Log builder.
//!
//! **Round-12 Gap 1 stub.** The pre-round-12 builder was tightly coupled to
//! the dropped `write_policy` / `governance_policy` SE fields, the `Est` /
//! `Evl` kinds, and the dual-incept paths (`incept` /
//! `incept_deterministic`). Gap 5 rebuilds this module end-to-end per
//! `~/.claude-plan-round12.md` (single `incept_chain`; `update`, `seal`,
//! `repair`, `contest`, `decommission`; pending bundling; `verify_server_chain_pre_action`).
//!
//! Until then, this module exposes the same public-method surface the
//! pre-round-12 callers used (`incept`, `incept_deterministic`, `update`,
//! `evaluate`, `repair`, `governance_policy`, `is_established`,
//! `events_since_evaluation`, `needs_evaluation`, `flush`, `publish_pending`)
//! so the workspace keeps compiling. Bodies that depend on the dropped SE
//! shape are stubbed to `Err(KelsError::InvalidKel("Gap 1 stub …"))` —
//! callers that exercise those paths at runtime fail immediately, which is
//! the right signal at this stage of the round.
//!
//! **Do not rely on this stub's semantics.** Gap 5 lands the real builder.

use std::sync::Arc;

use crate::{
    KelsError,
    client::SadStoreClient,
    store::SadStore,
    types::{PolicyChecker, SadEvent, SelVerification},
};

/// Outcome of a successful `SadEventBuilder::flush`. Same surface as the
/// pre-round-12 type — Gap 5 may extend.
#[derive(Debug, Clone)]
#[must_use = "FlushOutcome carries divergence signals — check diverged_at_at_submit"]
pub struct FlushOutcome {
    pub diverged_at_at_submit: Option<u64>,
    pub applied: bool,
}

/// Builder for SAD Event Logs — Gap 1 stub. See module docs.
///
/// `sad_store` and `checker` are held but unused in the stub bodies; they
/// stay so the `new` / `with_prefix` signatures match the pre-round-12
/// shape and Gap 5 has the deps it needs without re-threading construction.
#[allow(dead_code)]
pub struct SadEventBuilder {
    sad_client: Option<SadStoreClient>,
    sad_store: Option<Arc<dyn SadStore>>,
    checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
    sad_verification: Option<SelVerification>,
    pending_events: Vec<SadEvent>,
    requested_prefix: Option<cesr::Digest256>,
}

impl SadEventBuilder {
    /// Construct a bare builder.
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

    /// Hydrate verified state from the local SAD store at `sel_prefix`.
    ///
    /// Gap-1 stub keeps the round-10 owner-local hydration path so callers
    /// resuming an existing SE chain at construction time still see verified
    /// branch tips. Gap 5 will adapt the verifier wiring to take an
    /// `IelResolver` alongside the policy checker.
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

    /// Round-12 SE has no `governance_policy` field on events — policies
    /// live on IEL. Gap 1 stub returns `None` unconditionally; Gap 5
    /// removes this method entirely and routes governance through
    /// `IelResolver`.
    pub fn governance_policy(&self) -> Option<cesr::Digest256> {
        None
    }

    /// Round-12 stub: returns `true` once any event is present (pending or
    /// verified). The pre-round-12 distinction between "Icp" and
    /// "Icp+Est governance established" no longer exists — every chain has
    /// a permissionless Icp followed immediately by an Upd per the
    /// inception batch rule (Gap 4). Gap 5 removes this method entirely.
    pub fn is_established(&self) -> bool {
        self.sad_verification.is_some() || !self.pending_events.is_empty()
    }

    /// Round-12 stub: counts non-evaluation events on the pending tail.
    /// Treats `Sea` / `Rpr` / `Cnt` / `Dec` as evaluation events that reset
    /// the counter; everything else (Icp, Upd) increments. Gap 5 will
    /// recompute against the new branch state shape.
    pub fn events_since_evaluation(&self) -> usize {
        let mut count = self
            .sad_verification
            .as_ref()
            .map(|v| v.events_since_evaluation())
            .unwrap_or(0);
        for event in &self.pending_events {
            if event.kind.evaluates_governance() {
                count = 0;
            } else {
                count += 1;
            }
        }
        count
    }

    /// True when the next non-evaluation event would cross
    /// `MAX_NON_EVALUATION_EVENTS`. Gap 5 will replace with round-12-specific
    /// gates (e.g., post-divergence routing).
    pub fn needs_evaluation(&self) -> bool {
        self.events_since_evaluation() >= crate::MAX_NON_EVALUATION_EVENTS
    }

    // ==================== Staging — Gap 1 stubs ====================
    //
    // All staging methods below preserve the pre-round-12 signatures purely
    // so call sites compile during the Gap 1 → Gap 5 transition window.
    // Their bodies always error out: any caller that actually exercises a
    // staging path at runtime gets `KelsError::InvalidKel("Gap 1 stub: …")`
    // immediately, which is the right behavior — round-12 SE staging
    // requires the new IEL-binding flow that Gap 5 introduces.

    pub fn incept(
        &mut self,
        _topic: impl Into<String>,
        _identity_or_old_write_policy: cesr::Digest256,
        _old_governance_policy: cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError> {
        Err(stub_err("incept"))
    }

    pub fn incept_deterministic(
        &mut self,
        _topic: impl Into<String>,
        _identity_or_old_write_policy: cesr::Digest256,
        _old_governance_policy: cesr::Digest256,
        _content: Option<cesr::Digest256>,
    ) -> Result<(cesr::Digest256, cesr::Digest256), KelsError> {
        Err(stub_err("incept_deterministic"))
    }

    pub fn update(&mut self, _content: cesr::Digest256) -> Result<cesr::Digest256, KelsError> {
        Err(stub_err("update"))
    }

    pub fn evaluate(
        &mut self,
        _content: Option<cesr::Digest256>,
        _old_write_policy: Option<cesr::Digest256>,
        _old_governance_policy: Option<cesr::Digest256>,
    ) -> Result<cesr::Digest256, KelsError> {
        Err(stub_err("evaluate"))
    }

    pub async fn repair(
        &mut self,
        _content: Option<cesr::Digest256>,
    ) -> Result<cesr::Digest256, KelsError> {
        Err(stub_err("repair"))
    }

    // ==================== Submission ====================

    /// Submit pending events to SADStore. Gap-1 minimal version: posts
    /// pending events as-is and clears `pending_events` on success. The
    /// per-event policy/IEL re-verification that Gap 5 will run is omitted
    /// here — the stub is only used by callers that have already submitted
    /// events through other paths (e.g., gossip handlers) or by tests that
    /// don't depend on policy semantics.
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

    /// Flush staged events. Gap-1 stub: only meaningful when pending is
    /// already empty (returns a no-op `FlushOutcome`); otherwise errors —
    /// staging methods are stubbed, so a non-empty pending queue here is a
    /// caller bug.
    pub async fn flush(&mut self) -> Result<FlushOutcome, KelsError> {
        if self.pending_events.is_empty() {
            return Ok(FlushOutcome {
                diverged_at_at_submit: None,
                applied: false,
            });
        }
        Err(stub_err("flush"))
    }
}

fn stub_err(op: &str) -> KelsError {
    KelsError::InvalidKel(format!(
        "SadEventBuilder::{op} is a Gap-1 stub — round-12 SE staging \
         lands in Gap 5 (see ~/.claude-plan-round12.md)",
    ))
}
