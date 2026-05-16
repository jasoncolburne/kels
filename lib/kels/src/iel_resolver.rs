//! Production [`IelResolver`] implementation backed by an HTTP / paged IEL
//! source plus the `IelVerification` token.
//!
//! Lives in `lib/kels` (not `lib/policy`) so `SadEventBuilder` and friends
//! can construct one from their `SadStoreClient` without crossing the
//! kels-core / kels-policy crate boundary. The impl uses only kels-core
//! types — no policy-DSL machinery — so the placement is honest.
//!
//! The resolver re-verifies the named IEL on each call. Layered caching
//! lives above; this impl stays simple so the trait semantics — particularly
//! the divergence gate — are exercised cleanly.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use crate::{
    KelsError,
    types::{
        IdentityEvent, IelChainPosition, IelResolver, IelVerification, PagedIelSource,
        PolicyChecker, verify_identity_events_with_queried,
    },
};

/// `IelResolver` backed by a `PagedIelSource` (HTTP, in-memory, etc.) and a
/// `PolicyChecker`.
///
/// Each call walks the source to build (or rebuild) an `IelVerification`
/// token and uses its SAID-keyed accessors to satisfy the resolver contract.
/// The walk is bounded by `page_size` / `max_pages`; both fail-secure when
/// the chain exceeds the limit.
///
/// `queried_saids` is the set the SEL caller pre-walked from its own chain
/// (#147 follow-up). The resolver registers it on every `IelVerifier`
/// it constructs so `is_satisfied` answers consistently across calls. Set
/// once at construction via [`Self::with_queried_saids`]; lifetime of the
/// resolver = lifetime of the SEL verification it serves.
#[derive(Clone)]
pub struct AnchoredIelResolver {
    source: Arc<dyn PagedIelSource + Send + Sync>,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
    queried_saids: BTreeSet<cesr::Digest256>,
}

impl AnchoredIelResolver {
    pub fn new(
        source: Arc<dyn PagedIelSource + Send + Sync>,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
        page_size: usize,
        max_pages: usize,
    ) -> Self {
        Self {
            source,
            checker,
            page_size,
            max_pages,
            queried_saids: BTreeSet::new(),
        }
    }

    /// Register IEL event SAIDs the SEL caller cares about. Forwarded to
    /// every `IelVerifier` this resolver constructs so `is_satisfied`
    /// answers correctly.
    ///
    /// Caller pattern: SEL pre-walks its own chain (streaming over a
    /// `PagedSelSource`), accumulates `event.identity_event` SAIDs into a
    /// `BTreeSet`, then constructs the resolver via
    /// `AnchoredIelResolver::new(...).with_queried_saids(saids)`.
    #[must_use]
    pub fn with_queried_saids(mut self, saids: impl IntoIterator<Item = cesr::Digest256>) -> Self {
        self.queried_saids.extend(saids);
        self
    }

    async fn verification_for(
        &self,
        identity: &cesr::Digest256,
    ) -> Result<IelVerification, KelsError> {
        // #147 follow-up: delegate to the shared
        // `verify_identity_events_with_queried` helper so the page-walk +
        // verifier construction lives in one place. Forwards
        // `queried_saids` so the resulting token's `is_said_satisfied`
        // answers correctly.
        verify_identity_events_with_queried(
            identity,
            self.source.as_ref(),
            Arc::clone(&self.checker),
            self.page_size,
            self.max_pages,
            self.queried_saids.clone(),
        )
        .await
    }

    /// Materialize every event in the named IEL into a `said → event` map.
    /// Used by [`iel_chain_positions`]'s walk-back to determine the
    /// branch identity of post-divergence events without per-step HTTP
    /// fetches. Bounded by `max_pages`; fail-secure on overrun (so the
    /// walk-back never runs against an incomplete map and silently
    /// returns "event not found").
    async fn collect_all_events(
        &self,
        identity: &cesr::Digest256,
    ) -> Result<HashMap<cesr::Digest256, IdentityEvent>, KelsError> {
        let mut found: HashMap<cesr::Digest256, IdentityEvent> = HashMap::new();
        let mut since: Option<cesr::Digest256> = None;
        let mut exhausted = false;
        for _ in 0..self.max_pages {
            let (events, has_more) = self
                .source
                .fetch_page(identity, since.as_ref(), self.page_size)
                .await?;
            if events.is_empty() {
                exhausted = true;
                break;
            }
            for event in &events {
                if &event.prefix != identity {
                    return Err(KelsError::identity_binding_violation(format!(
                        "IEL event {} has prefix {} but expected identity {} \
                         (cross-IEL contamination)",
                        event.said, event.prefix, identity,
                    )));
                }
                found.insert(event.said, event.clone());
            }
            if !has_more {
                exhausted = true;
                break;
            }
            since = events.last().map(|e| e.said);
        }
        if !exhausted {
            return Err(KelsError::InvalidIel(format!(
                "IEL walk-back materialization exceeded max_pages limit ({}) for {}",
                self.max_pages, identity,
            )));
        }
        Ok(found)
    }

    /// Walk the source until `wanted` (a set of SAIDs) are all collected, or
    /// the chain ends / `max_pages` is exhausted. Returns events in their
    /// canonical chain order. Used by [`fetch_iel_event`] and
    /// [`iel_chain_positions`] to avoid duplicating the page walk.
    async fn collect_events_by_said(
        &self,
        identity: &cesr::Digest256,
        wanted: &[cesr::Digest256],
    ) -> Result<HashMap<cesr::Digest256, IdentityEvent>, KelsError> {
        let mut found: HashMap<cesr::Digest256, IdentityEvent> = HashMap::new();
        if wanted.is_empty() {
            return Ok(found);
        }

        let mut since: Option<cesr::Digest256> = None;
        for _ in 0..self.max_pages {
            let (events, has_more) = self
                .source
                .fetch_page(identity, since.as_ref(), self.page_size)
                .await?;
            if events.is_empty() {
                break;
            }
            for event in &events {
                if wanted.iter().any(|w| w == &event.said) && !found.contains_key(&event.said) {
                    if &event.prefix != identity {
                        return Err(KelsError::identity_binding_violation(format!(
                            "IEL event {} has prefix {} but expected identity {} \
                             (cross-IEL contamination)",
                            event.said, event.prefix, identity,
                        )));
                    }
                    found.insert(event.said, event.clone());
                }
            }
            if found.len() == wanted.len() {
                return Ok(found);
            }
            if !has_more {
                break;
            }
            since = events.last().map(|e| e.said);
        }

        Ok(found)
    }
}

#[async_trait::async_trait]
impl IelResolver for AnchoredIelResolver {
    async fn fetch_iel_event(
        &self,
        identity: &cesr::Digest256,
        iel_event_said: &cesr::Digest256,
    ) -> Result<IdentityEvent, KelsError> {
        let mut found = self
            .collect_events_by_said(identity, std::slice::from_ref(iel_event_said))
            .await?;
        found
            .remove(iel_event_said)
            .ok_or_else(|| KelsError::missing_iel_event(*identity, *iel_event_said))
    }

    async fn resolve_auth_policy_at(
        &self,
        identity: &cesr::Digest256,
        iel_event_said: &cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError> {
        let bound = self.fetch_iel_event(identity, iel_event_said).await?;
        let verification = self.verification_for(identity).await?;
        if let Some(divergence_at) = verification.diverged_at_version()
            && bound.version >= divergence_at
        {
            return Err(KelsError::IelDivergent(format!(
                "IEL event {} bound at version {} sits at-or-after divergence at version {}",
                iel_event_said, bound.version, divergence_at,
            )));
        }
        verification.auth_policy_at(iel_event_said).ok_or_else(|| {
            KelsError::identity_binding_violation(format!(
                "auth_policy not found for IEL event {} in IEL {} \
                 (event not in policy_history — chain integrity breach)",
                iel_event_said, identity,
            ))
        })
    }

    async fn resolve_governance_policy_at(
        &self,
        identity: &cesr::Digest256,
        iel_event_said: &cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError> {
        let bound = self.fetch_iel_event(identity, iel_event_said).await?;
        let verification = self.verification_for(identity).await?;
        if let Some(divergence_at) = verification.diverged_at_version()
            && bound.version >= divergence_at
        {
            return Err(KelsError::IelDivergent(format!(
                "IEL event {} bound at version {} sits at-or-after divergence at version {}",
                iel_event_said, bound.version, divergence_at,
            )));
        }
        verification
            .governance_policy_at(iel_event_said)
            .ok_or_else(|| {
                KelsError::identity_binding_violation(format!(
                    "governance_policy not found for IEL event {} in IEL {} \
                     (event not in policy_history — chain integrity breach)",
                    iel_event_said, identity,
                ))
            })
    }

    async fn is_satisfied(
        &self,
        identity: &cesr::Digest256,
        said: &cesr::Digest256,
    ) -> Result<crate::IelSatisfaction, KelsError> {
        // The verifier walks the IEL with `queried_saids` registered (set
        // at construction). After the walk, `is_said_satisfied` is the
        // direct answer. The fetch step doubles as the chain-integrity
        // check: missing-by-SAID surfaces `MissingIelEvent`, which we
        // re-classify into `IelSatisfaction::MissingEvent` (deferrable);
        // cross-IEL contamination surfaces `IdentityBindingViolation`,
        // re-classified into `IelSatisfaction::PermanentFailure`. In-chain
        // auth-fail surfaces as `IelSatisfaction::AuthFailed` (the SEL
        // verifier's soft-eligible carve-out path; wire-permanent).
        match self.fetch_iel_event(identity, said).await {
            Ok(_) => {}
            Err(KelsError::MissingIelEvent(dep)) => {
                return Ok(crate::IelSatisfaction::MissingEvent {
                    iel_prefix: dep.iel_prefix,
                    event_said: dep.event_said,
                });
            }
            Err(KelsError::IdentityBindingViolation(violation)) => {
                return Ok(crate::IelSatisfaction::PermanentFailure(violation));
            }
            Err(other) => return Err(other),
        }
        let verification = self.verification_for(identity).await?;
        if verification.is_said_satisfied(said) {
            Ok(crate::IelSatisfaction::Satisfied)
        } else {
            Ok(crate::IelSatisfaction::AuthFailed {
                reason: format!(
                    "IEL event {} did not satisfy IEL verification \
                     (auth-fail or post-IEL-divergence soft) in IEL {}",
                    said, identity,
                ),
            })
        }
    }

    async fn iel_chain_positions(
        &self,
        identity: &cesr::Digest256,
        saids: &[cesr::Digest256],
    ) -> Result<crate::IelChainPositionBatch, KelsError> {
        if saids.is_empty() {
            return Ok(crate::IelChainPositionBatch {
                found: Vec::new(),
                missing: Vec::new(),
            });
        }

        // Dedup input per the partial-results contract — multiple callers
        // may pass the same SAID twice, and the wire-format dep emission
        // upstream wants distinct entries.
        let mut deduped: Vec<cesr::Digest256> = saids.to_vec();
        deduped.sort();
        deduped.dedup();

        // One verification call to learn the divergence point.
        let verification = self.verification_for(identity).await?;
        let diverged_at = verification.diverged_at_version();

        // For non-divergent IELs walk-back never fires; we only need the
        // specifically requested events. For divergent IELs we materialize
        // every event in one extra page walk and walk back in-memory, so
        // each post-divergence SAID resolves its branch identity in
        // O(divergent-depth) hashmap hops with no extra HTTP cost.
        let chain = if diverged_at.is_some() {
            self.collect_all_events(identity).await?
        } else {
            self.collect_events_by_said(identity, &deduped).await?
        };

        let mut found: Vec<IelChainPosition> = Vec::new();
        let mut missing: Vec<cesr::Digest256> = Vec::new();
        for said in &deduped {
            let Some(event) = chain.get(said) else {
                missing.push(*said);
                continue;
            };

            // #147 follow-up: walk back from each post-divergence
            // SAID to its branch's first-divergent ancestor. The ancestor's
            // SAID becomes the branch identity, so two events on the same
            // branch share a `branch_marker` and compare via canonical
            // chain order (instead of surfacing a false-positive
            // `IelDivergent`). Pre-divergence events keep `None`.
            let branch_marker = match diverged_at {
                Some(threshold) if event.version >= threshold => Some(
                    walk_back_to_branch_identity(&chain, *said, threshold, identity)?,
                ),
                _ => None,
            };

            found.push(IelChainPosition {
                version: event.version,
                kind: event.kind,
                said: event.said,
                branch_marker,
            });
        }

        Ok(crate::IelChainPositionBatch { found, missing })
    }

    async fn resolve_identity_for_event(
        &self,
        iel_event_said: &cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError> {
        // Single-event said-form fetch via the source's said-keyed endpoint.
        // Limit 1 — we only need any one event from the chain to read its
        // prefix (every event on an IEL carries the same prefix).
        let (events, _) = self
            .source
            .fetch_page_by_event_said(iel_event_said, None, 1)
            .await?;
        events.into_iter().next().map(|e| e.prefix).ok_or_else(|| {
            // No locally-known IEL contains this event SAID. We don't have
            // an `iel_prefix` to populate `MissingIelEvent` — the caller
            // (e.g., `verify_custody_write`) is the one with that context
            // (or, in the SAD-object custody.write case, has only the SAID
            // itself). Mark as permanent here; the deferred-deps layer at
            // the handler can re-classify on its own when it knows the
            // context. Tracked: this is the SAID-only-cannot-defer corner
            // of #156 / #167 which custody.write ultimately resolves at the
            // sadstore handler layer.
            KelsError::identity_binding_violation(format!(
                "IEL event {} not found in any locally-known IEL",
                iel_event_said,
            ))
        })
    }

    async fn resolve_current_auth_policy(
        &self,
        identity: &cesr::Digest256,
    ) -> Result<cesr::Digest256, KelsError> {
        let verification = self.verification_for(identity).await?;
        if verification.is_contested() {
            return Err(KelsError::ContestedIel(format!(
                "IEL {} is contested",
                identity,
            )));
        }
        if verification.is_decommissioned() {
            return Err(KelsError::IelDecommissioned(format!(
                "IEL {} is decommissioned",
                identity,
            )));
        }
        if verification.is_divergent() {
            return Err(KelsError::IelDivergent(format!(
                "IEL {} is divergent — no canonical current auth_policy",
                identity,
            )));
        }
        let tip = verification.current_event().ok_or_else(|| {
            KelsError::NotFound(format!(
                "IEL {} has no current event — chain not locally known",
                identity,
            ))
        })?;
        verification.auth_policy_at(&tip.said).ok_or_else(|| {
            KelsError::InvalidIel(format!(
                "IEL {} tip event {} has no auth_policy in policy_history \
                 (chain integrity breach)",
                identity, tip.said,
            ))
        })
    }
}

/// Walk `event.previous` from `start` until reaching the event at version
/// `divergence_version`. That event's SAID is the branch identity for any
/// post-divergence event tracing back through it. Bounded by `chain.len()`
/// to detect cycles or unbounded loops.
///
/// Returns `KelsError::IdentityBindingViolation` on any chain-integrity
/// breach mid-walk: missing event, walked past `divergence_version`,
/// `previous=None` on a non-Icp event, or step-bound exceeded.
///
/// #147 follow-up: shared walker used by both
/// [`AnchoredIelResolver::iel_chain_positions`] and the in-process
/// `RepositoryIelResolver` (in `services/sadstore`). Each impl supplies
/// its own materialized chain map; the algorithm is identical.
pub fn walk_back_to_branch_identity(
    chain: &HashMap<cesr::Digest256, IdentityEvent>,
    start: cesr::Digest256,
    divergence_version: u64,
    identity: &cesr::Digest256,
) -> Result<cesr::Digest256, KelsError> {
    let mut current = start;
    let bound = chain.len() + 1;
    for _ in 0..bound {
        let event = chain.get(&current).ok_or_else(|| {
            KelsError::identity_binding_violation(format!(
                "IEL walk-back: event {} not found in IEL {} (chain integrity breach)",
                current, identity,
            ))
        })?;
        if event.version == divergence_version {
            return Ok(event.said);
        }
        if event.version < divergence_version {
            return Err(KelsError::identity_binding_violation(format!(
                "IEL walk-back: event {} at version {} walked past divergence \
                 at version {} (chain integrity breach)",
                current, event.version, divergence_version,
            )));
        }
        current = event.previous.ok_or_else(|| {
            KelsError::identity_binding_violation(format!(
                "IEL walk-back: event {} at version {} has no previous \
                 (chain integrity breach)",
                current, event.version,
            ))
        })?;
    }
    Err(KelsError::identity_binding_violation(format!(
        "IEL walk-back: exceeded chain length bound for IEL {} \
         (cycle or chain too long)",
        identity,
    )))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::cmp::Ordering;

    use crate::types::IdentityEventKind;

    const TEST_TOPIC: &str = "kels/iel/v1/identity/walk-back";

    fn d(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    /// Test fake serving a fixed list of IEL events in order, paginating by
    /// exclusive `since` SAID.
    struct VecSource {
        events: Vec<IdentityEvent>,
    }

    #[async_trait]
    impl PagedIelSource for VecSource {
        async fn fetch_page(
            &self,
            _prefix: &cesr::Digest256,
            since: Option<&cesr::Digest256>,
            limit: usize,
        ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
            let start = match since {
                None => 0,
                Some(cursor) => self
                    .events
                    .iter()
                    .position(|e| &e.said == cursor)
                    .map(|i| i + 1)
                    .unwrap_or(self.events.len()),
            };
            if start >= self.events.len() {
                return Ok((Vec::new(), false));
            }
            let end = (start + limit).min(self.events.len());
            let page = self.events[start..end].to_vec();
            let has_more = end < self.events.len();
            Ok((page, has_more))
        }
    }

    /// Anchor check passes for everything; every policy is immune.
    struct AlwaysPassChecker;

    #[async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn evaluate(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<crate::types::AnchorEvaluation, KelsError> {
            Ok(crate::types::AnchorEvaluation {
                satisfied: true,
                missing_anchors: Vec::new(),
            })
        }
        async fn is_immune(&self, _: &cesr::Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    /// Build a divergent IEL chain in canonical sort order:
    /// `Icp@v=0`, `Evl_a@v=1`, `Evl_b@v=1` (lower SAID first), and a
    /// post-divergence `Evl_a2@v=2` extending `Evl_a`. Returns the events
    /// plus the lower-SAID branch's tip SAID at v=1 so tests can assert
    /// branch identity directly.
    fn build_divergent_chain() -> (
        Vec<IdentityEvent>,
        IdentityEvent,
        IdentityEvent,
        IdentityEvent,
    ) {
        let auth = d(b"auth-policy");
        let gov = d(b"gov-policy");
        let icp = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        // Two competing Evls at v=1: differentiated by carrying different
        // auth_policy values forward (constructors derive distinct SAIDs).
        let auth_a = d(b"auth-policy-A");
        let auth_b = d(b"auth-policy-B");
        let evl_a = IdentityEvent::evl(&icp, Some(auth_a), None).unwrap();
        let evl_b = IdentityEvent::evl(&icp, Some(auth_b), None).unwrap();
        // Order canonically: kind sort_priority is equal (both Evl), tiebreak by SAID.
        let (lo, hi) = if evl_a.said.as_ref() < evl_b.said.as_ref() {
            (evl_a.clone(), evl_b.clone())
        } else {
            (evl_b.clone(), evl_a.clone())
        };
        // Post-divergence event extending the lower-SAID branch tip. Only
        // `Cnt` is allowed on a divergent IEL (#171: divergence = compromise;
        // Cnt is the owner's testimony "this IEL is no longer authoritative").
        let cnt_lo_v2 = IdentityEvent::cnt(&lo).unwrap();
        let chain = vec![icp.clone(), lo.clone(), hi.clone(), cnt_lo_v2.clone()];
        (chain, lo, hi, cnt_lo_v2)
    }

    fn resolver(events: Vec<IdentityEvent>) -> AnchoredIelResolver {
        AnchoredIelResolver::new(
            Arc::new(VecSource { events }),
            Arc::new(AlwaysPassChecker),
            crate::page_size(),
            crate::max_pages(),
        )
    }

    #[tokio::test]
    async fn walk_back_identifies_branch_for_distinct_post_divergence_events_on_same_branch() {
        let (chain, lo_v1, _hi_v1, lo_v2) = build_divergent_chain();
        let identity = chain[0].prefix;
        let r = resolver(chain);

        let positions = r
            .iel_chain_positions(&identity, &[lo_v1.said, lo_v2.said])
            .await
            .expect("positions resolve");

        let p_v1 = positions.get(&lo_v1.said).expect("v1 position");
        let p_v2 = positions.get(&lo_v2.said).expect("v2 position");

        // Both events on the same branch share the same branch identity:
        // the v=1 ancestor on this branch is `lo_v1` itself.
        assert_eq!(p_v1.branch_marker, Some(lo_v1.said));
        assert_eq!(p_v2.branch_marker, Some(lo_v1.said));

        // Same-branch positions compare by canonical chain order (Less / Greater),
        // not IelDivergent.
        assert_eq!(p_v1.try_cmp(p_v2).unwrap(), Ordering::Less);
        assert_eq!(p_v2.try_cmp(p_v1).unwrap(), Ordering::Greater);
    }

    #[tokio::test]
    async fn walk_back_identifies_branch_for_events_on_different_branches() {
        let (chain, lo_v1, hi_v1, _lo_v2) = build_divergent_chain();
        let identity = chain[0].prefix;
        let r = resolver(chain);

        let positions = r
            .iel_chain_positions(&identity, &[lo_v1.said, hi_v1.said])
            .await
            .expect("positions resolve");

        let p_lo = positions.get(&lo_v1.said).expect("lo branch position");
        let p_hi = positions.get(&hi_v1.said).expect("hi branch position");

        // Each event sits at v=D (the divergence version), so its own SAID
        // is the branch identity.
        assert_eq!(p_lo.branch_marker, Some(lo_v1.said));
        assert_eq!(p_hi.branch_marker, Some(hi_v1.said));

        // Different branches → IelDivergent (no canonical ordering across
        // forks).
        assert!(matches!(
            p_lo.try_cmp(p_hi),
            Err(KelsError::IelDivergent(_))
        ));
        assert!(matches!(
            p_hi.try_cmp(p_lo),
            Err(KelsError::IelDivergent(_))
        ));
    }

    #[tokio::test]
    async fn pre_divergence_event_has_no_branch_marker() {
        let (chain, _lo, _hi, _lo_v2) = build_divergent_chain();
        let identity = chain[0].prefix;
        let icp = chain[0].clone();
        let r = resolver(chain);

        let positions = r
            .iel_chain_positions(&identity, &[icp.said])
            .await
            .expect("positions resolve");
        let p = positions.get(&icp.said).expect("icp position");
        assert!(p.branch_marker.is_none());
    }

    // Suppress the "kind is unused" warning if we don't reference IdentityEventKind.
    #[allow(dead_code)]
    fn _silence_kind() -> IdentityEventKind {
        IdentityEventKind::Evl
    }
}
