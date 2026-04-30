//! Production [`IelResolver`] implementation backed by an HTTP / paged IEL
//! source plus the round-11 `IelVerification` token.
//!
//! Lives in `lib/kels` (not `lib/policy`) so `SadEventBuilder` and friends
//! can construct one from their `SadStoreClient` without crossing the
//! kels-core / kels-policy crate boundary. The impl uses only kels-core
//! types — no policy-DSL machinery — so the placement is honest.
//!
//! The resolver re-verifies the named IEL on each call. Layered caching
//! lives above; this impl stays simple so the trait semantics — particularly
//! the divergence gate — are exercised cleanly.

use std::{collections::HashMap, sync::Arc};

use crate::{
    KelsError,
    types::{
        IdentityEvent, IelChainPosition, IelResolver, IelVerification, PagedIelSource,
        PolicyChecker, verify_identity_events,
    },
};

/// `IelResolver` backed by a `PagedIelSource` (HTTP, in-memory, etc.) and a
/// `PolicyChecker`.
///
/// Each call walks the source to build (or rebuild) an `IelVerification`
/// token and uses its SAID-keyed accessors to satisfy the resolver contract.
/// The walk is bounded by `page_size` / `max_pages`; both fail-secure when
/// the chain exceeds the limit.
#[derive(Clone)]
pub struct AnchoredIelResolver {
    source: Arc<dyn PagedIelSource + Send + Sync>,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    page_size: usize,
    max_pages: usize,
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
        }
    }

    async fn verification_for(
        &self,
        identity: &cesr::Digest256,
    ) -> Result<IelVerification, KelsError> {
        verify_identity_events(
            identity,
            self.source.as_ref(),
            Arc::clone(&self.checker),
            self.page_size,
            self.max_pages,
        )
        .await
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
                        return Err(KelsError::BadIdentityBinding(format!(
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
        found.remove(iel_event_said).ok_or_else(|| {
            KelsError::BadIdentityBinding(format!(
                "IEL event {} not found in IEL {}",
                iel_event_said, identity
            ))
        })
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
            KelsError::BadIdentityBinding(format!(
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
                KelsError::BadIdentityBinding(format!(
                    "governance_policy not found for IEL event {} in IEL {} \
                     (event not in policy_history — chain integrity breach)",
                    iel_event_said, identity,
                ))
            })
    }

    async fn iel_chain_positions(
        &self,
        identity: &cesr::Digest256,
        saids: &[cesr::Digest256],
    ) -> Result<HashMap<cesr::Digest256, IelChainPosition>, KelsError> {
        if saids.is_empty() {
            return Ok(HashMap::new());
        }

        // One verification call to learn the divergence point.
        let verification = self.verification_for(identity).await?;
        let diverged_at = verification.diverged_at_version();

        // One source walk to fetch every requested event.
        let found = self.collect_events_by_said(identity, saids).await?;

        let mut positions: HashMap<cesr::Digest256, IelChainPosition> = HashMap::new();
        for said in saids {
            let event = found.get(said).ok_or_else(|| {
                KelsError::BadIdentityBinding(format!(
                    "IEL event {} not found in IEL {} (requested for monotonic ratchet)",
                    said, identity,
                ))
            })?;

            // Per round-12 verifier discipline, post-divergence events are
            // structurally unreachable as ratchet inputs (see Gap 2's
            // monotonic-ratchet "Update precondition"). When seen anyway,
            // mark them with the event's own SAID so two such positions
            // would only compare-equal when `said == said`; differing SAIDs
            // surface `IelDivergent` from `IelChainPosition::try_cmp` —
            // matching the trait's case-4 behavior. A precise branch-walk
            // implementation can layer in later if real divergent-position
            // comparisons are ever introduced.
            let branch_marker = match diverged_at {
                Some(threshold) if event.version >= threshold => Some(event.said),
                _ => None,
            };

            positions.insert(
                *said,
                IelChainPosition {
                    version: event.version,
                    kind: event.kind,
                    said: event.said,
                    branch_marker,
                },
            );
        }

        Ok(positions)
    }
}
