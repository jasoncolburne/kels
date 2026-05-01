//! In-process [`IelResolver`](kels_core::IelResolver) backed by
//! [`SadStoreRepository`](crate::repository::SadStoreRepository).
//!
//! The SE submit handler runs in the same process as the IEL repository,
//! so cross-chain reads go through this struct rather than through
//! `kels_core::AnchoredIelResolver` (which page-walks an HTTP source).
//! This impl issues per-SAID lookups against the IEL events table and
//! gates `resolve_*_at` on `first_divergent_version` per the trait
//! contract. `iel_chain_positions` walks back from each post-divergence
//! SAID via `fetch_event_by_said` to determine its branch identity
//! (round-12 third follow-up).

use std::{collections::BTreeSet, sync::Arc};

use crate::repository::SadStoreRepository;

/// In-process [`IelResolver`](kels_core::IelResolver) backed directly by
/// the SAD store's `IdentityEventRepository`.
///
/// Construct via [`Self::new`]; register the SE caller's pre-walked
/// identity_event SAIDs via [`Self::with_queried_saids`] so `is_satisfied`
/// answers consistently across calls.
pub struct RepositoryIelResolver {
    repo: Arc<SadStoreRepository>,
    /// `PolicyChecker` used by the in-process `IelVerifier` walks inside
    /// `is_satisfied`. Same checker the SE handler builds for its own
    /// `SelVerifier` — passing it here keeps the IEL-side auth check
    /// answer-equivalent to the IEL submit handler's own walk.
    checker: Arc<dyn kels_core::PolicyChecker + Send + Sync>,
    /// SE caller's pre-walked identity_event SAIDs. Forwarded to the
    /// `IelVerifier` constructed in `is_satisfied` via `check_satisfied`.
    /// Empty until `with_queried_saids` is called.
    queried_saids: BTreeSet<cesr::Digest256>,
}

impl RepositoryIelResolver {
    pub fn new(
        repo: Arc<SadStoreRepository>,
        checker: Arc<dyn kels_core::PolicyChecker + Send + Sync>,
    ) -> Self {
        Self {
            repo,
            checker,
            queried_saids: BTreeSet::new(),
        }
    }

    /// Register the SE caller's pre-walked queried SAIDs for satisfaction
    /// tracking. Mirrors `AnchoredIelResolver::with_queried_saids`.
    #[must_use]
    pub fn with_queried_saids(mut self, saids: impl IntoIterator<Item = cesr::Digest256>) -> Self {
        self.queried_saids.extend(saids);
        self
    }

    async fn fetch_event_by_said(
        &self,
        said: &cesr::Digest256,
    ) -> Result<Option<kels_core::IdentityEvent>, kels_core::KelsError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query =
            verifiable_storage_postgres::Query::<kels_core::IdentityEvent>::for_table("iel_events")
                .eq("said", said.as_ref())
                .limit(1);
        self.repo
            .iel_events
            .pool
            .fetch(query)
            .await
            .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))
            .map(|mut v| v.pop())
    }
}

#[async_trait::async_trait]
impl kels_core::IelResolver for RepositoryIelResolver {
    async fn fetch_iel_event(
        &self,
        identity: &cesr::Digest256,
        iel_event_said: &cesr::Digest256,
    ) -> Result<kels_core::IdentityEvent, kels_core::KelsError> {
        let event = self
            .fetch_event_by_said(iel_event_said)
            .await?
            .ok_or_else(|| {
                kels_core::KelsError::BadIdentityBinding(format!(
                    "IEL event {} not found in IEL {}",
                    iel_event_said, identity
                ))
            })?;
        if event.prefix != *identity {
            return Err(kels_core::KelsError::BadIdentityBinding(format!(
                "IEL event {} has prefix {} but expected identity {} \
                 (cross-IEL contamination)",
                iel_event_said, event.prefix, identity
            )));
        }
        Ok(event)
    }

    async fn resolve_auth_policy_at(
        &self,
        identity: &cesr::Digest256,
        iel_event_said: &cesr::Digest256,
    ) -> Result<cesr::Digest256, kels_core::KelsError> {
        let event = self.fetch_iel_event(identity, iel_event_said).await?;
        let divergent_at = self
            .repo
            .iel_events
            .first_divergent_version(identity)
            .await
            .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))?;
        if let Some(d) = divergent_at
            && event.version >= d
        {
            return Err(kels_core::KelsError::IelDivergent(format!(
                "IEL event {} bound at version {} sits at-or-after divergence {}",
                iel_event_said, event.version, d
            )));
        }
        Ok(event.auth_policy)
    }

    async fn resolve_governance_policy_at(
        &self,
        identity: &cesr::Digest256,
        iel_event_said: &cesr::Digest256,
    ) -> Result<cesr::Digest256, kels_core::KelsError> {
        let event = self.fetch_iel_event(identity, iel_event_said).await?;
        let divergent_at = self
            .repo
            .iel_events
            .first_divergent_version(identity)
            .await
            .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))?;
        if let Some(d) = divergent_at
            && event.version >= d
        {
            return Err(kels_core::KelsError::IelDivergent(format!(
                "IEL event {} bound at version {} sits at-or-after divergence {}",
                iel_event_said, event.version, d
            )));
        }
        Ok(event.governance_policy)
    }

    async fn is_satisfied(
        &self,
        identity: &cesr::Digest256,
        said: &cesr::Digest256,
    ) -> Result<bool, kels_core::KelsError> {
        // Chain-integrity check: BadIdentityBinding propagates from
        // fetch_iel_event if the SAID isn't in the named IEL or has a
        // prefix mismatch. After that, walk the IEL via the repo,
        // running an `IelVerifier` with `queried_saids ∪ {said}`
        // registered, then read `is_said_satisfied(said)` from the token.
        let _ = self.fetch_iel_event(identity, said).await?;

        // Pool-based paged walk (non-transactional — `is_satisfied` is
        // called from inside the SE submit transaction but the IEL state
        // is read-only here; same isolation as the pre-batch
        // `is_divergent` / `first_divergent_version` queries the SE
        // handler already does).
        use verifiable_storage_postgres::QueryExecutor;
        let mut verifier = kels_core::IelVerifier::new(Some(identity), self.checker.clone());
        verifier.check_satisfied(self.queried_saids.iter().copied());
        verifier.check_satisfied([*said]);

        let page_size = kels_core::page_size() as u64;
        let max_pages = kels_core::max_pages();
        let mut since: Option<cesr::Digest256> = None;
        for _ in 0..max_pages {
            // Fetch a page from the IEL repo via the pool (no transaction).
            let mut query =
                verifiable_storage_postgres::Query::<kels_core::IdentityEvent>::for_table(
                    "iel_events",
                )
                .eq("prefix", identity.as_ref())
                .order_by("version", verifiable_storage_postgres::Order::Asc)
                .order_by_case(
                    "kind",
                    &kels_core::IdentityEventKind::sort_priority_mapping(),
                    verifiable_storage_postgres::Order::Asc,
                )
                .order_by("said", verifiable_storage_postgres::Order::Asc)
                .limit(page_size);
            if let Some(s) = since {
                // Approximate: include only events whose version is >= the
                // since cursor's version. Final monotonic-ratchet ordering
                // already enforced by the canonical sort.
                if let Some(prev) = self.fetch_event_by_said(&s).await? {
                    query = query.gte("version", prev.version);
                }
            }
            let events: Vec<kels_core::IdentityEvent> = self
                .repo
                .iel_events
                .pool
                .fetch(query)
                .await
                .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))?;
            if events.is_empty() {
                break;
            }
            let last_said = events.last().map(|e| e.said);
            verifier.verify_page(&events).await?;
            if (events.len() as u64) < page_size {
                break;
            }
            since = last_said;
        }

        let verification = verifier.finish().await?;
        Ok(verification.is_said_satisfied(said))
    }

    async fn iel_chain_positions(
        &self,
        identity: &cesr::Digest256,
        saids: &[cesr::Digest256],
    ) -> Result<
        std::collections::HashMap<cesr::Digest256, kels_core::IelChainPosition>,
        kels_core::KelsError,
    > {
        if saids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let divergent_at = self
            .repo
            .iel_events
            .first_divergent_version(identity)
            .await
            .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))?;

        let mut out = std::collections::HashMap::new();
        for said in saids {
            let event = self.fetch_iel_event(identity, said).await?;
            // Round-12 third follow-up: walk back from each post-divergence
            // SAID via `fetch_event_by_said` until reaching the event at
            // version `divergent_at`. That ancestor's SAID is the branch
            // identity. O(K·D) per-batch — D≈1–2 in production.
            let branch_marker = match divergent_at {
                Some(d) if event.version >= d => Some(
                    self.walk_back_to_branch_identity(identity, &event, d)
                        .await?,
                ),
                _ => None,
            };
            out.insert(
                *said,
                kels_core::IelChainPosition {
                    version: event.version,
                    kind: event.kind,
                    said: *said,
                    branch_marker,
                },
            );
        }
        Ok(out)
    }
}

impl RepositoryIelResolver {
    /// Walk `event.previous` from `start` until reaching the event at
    /// version `divergence_version` and return that ancestor's SAID. The
    /// returned SAID is the branch identity for any post-divergence event
    /// tracing back through it. Per-step lookups via `fetch_event_by_said`.
    ///
    /// Returns `BadIdentityBinding` on chain-integrity breaches: missing
    /// event, walked past `divergence_version`, `previous=None` mid-walk,
    /// or step bound exceeded.
    async fn walk_back_to_branch_identity(
        &self,
        identity: &cesr::Digest256,
        start: &kels_core::IdentityEvent,
        divergence_version: u64,
    ) -> Result<cesr::Digest256, kels_core::KelsError> {
        let mut current = start.clone();
        // Step bound: walking from V_S to D takes (V_S - D) steps. Bounded
        // by `max_pages × page_size` (the chain-length ceiling).
        let bound = kels_core::max_pages().saturating_mul(kels_core::page_size()) + 1;
        for _ in 0..bound {
            if current.version == divergence_version {
                return Ok(current.said);
            }
            if current.version < divergence_version {
                return Err(kels_core::KelsError::BadIdentityBinding(format!(
                    "IEL walk-back: event {} at version {} walked past divergence \
                     at version {} (chain integrity breach)",
                    current.said, current.version, divergence_version,
                )));
            }
            let prev_said = current.previous.ok_or_else(|| {
                kels_core::KelsError::BadIdentityBinding(format!(
                    "IEL walk-back: event {} at version {} has no previous \
                     (chain integrity breach)",
                    current.said, current.version,
                ))
            })?;
            let prev_event = self.fetch_event_by_said(&prev_said).await?.ok_or_else(|| {
                kels_core::KelsError::BadIdentityBinding(format!(
                    "IEL walk-back: previous event {} not found in IEL {} \
                         (chain integrity breach)",
                    prev_said, identity,
                ))
            })?;
            if prev_event.prefix != *identity {
                return Err(kels_core::KelsError::BadIdentityBinding(format!(
                    "IEL walk-back: event {} has prefix {} but expected {} \
                     (cross-IEL contamination)",
                    prev_said, prev_event.prefix, identity,
                )));
            }
            current = prev_event;
        }
        Err(kels_core::KelsError::BadIdentityBinding(format!(
            "IEL walk-back: exceeded chain length bound for IEL {} \
             (cycle or chain too long)",
            identity,
        )))
    }
}
