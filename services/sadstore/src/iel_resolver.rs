//! In-process [`IelResolver`](kels_core::IelResolver) backed by
//! [`SadStoreRepository`](crate::repository::SadStoreRepository).
//!
//! The SEL submit handler runs in the same process as the IEL repository,
//! so cross-chain reads go through this struct rather than through
//! `kels_core::AnchoredIelResolver` (which page-walks an HTTP source).
//! This impl issues per-SAID lookups against the IEL events table and
//! gates `resolve_*_at` on `first_divergent_version` per the trait
//! contract. `iel_chain_positions` walks back from each post-divergence
//! SAID via `fetch_event_by_said` to determine its branch identity
//! (#147 follow-up).

use std::{collections::BTreeSet, sync::Arc};

use crate::repository::SadStoreRepository;

/// `PagedIelSource` adapter wrapping the IEL repository's connection pool.
/// Mirrors `HttpIelSource`'s shape for the in-process path so the shared
/// IEL verification helper (`verify_identity_events_with_queried`) can
/// drive the walk for both HTTP and in-process callers.
///
/// Reads are non-transactional — the SEL submit transaction wrapping
/// `is_satisfied` isolates SEL state; IEL state is read-only here so pool
/// reads (consistent with the SEL handler's pre-batch
/// `is_divergent` / `first_divergent_version` queries) are correct.
struct RepositoryIelPageSource {
    repo: Arc<SadStoreRepository>,
}

#[async_trait::async_trait]
impl kels_core::PagedIelSource for RepositoryIelPageSource {
    async fn fetch_page(
        &self,
        prefix: &cesr::Digest256,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<(Vec<kels_core::IdentityEvent>, bool), kels_core::KelsError> {
        let prefix_str = prefix.to_string();
        let since_str = since.map(|s| s.to_string());
        let events = self
            .repo
            .iel_events
            .fetch_iel_page_pool(
                crate::repository::IelChainSelector::Prefix(&prefix_str),
                since_str.as_deref(),
                Some(limit as u64),
            )
            .await
            .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))?;
        // The shared helper relies on `has_more` to decide whether to
        // continue paging. A full-limit page implies more events may
        // exist; a short page guarantees end-of-chain (post-filtered to
        // strict-gt semantics in `fetch_iel_page_pool`).
        let has_more = events.len() == limit;
        Ok((events, has_more))
    }
}

/// In-process [`IelResolver`](kels_core::IelResolver) backed directly by
/// the SAD store's `IdentityEventRepository`.
///
/// Construct via [`Self::new`]; register the SEL caller's pre-walked
/// identity_event SAIDs via [`Self::with_queried_saids`] so `is_satisfied`
/// answers consistently across calls.
pub struct RepositoryIelResolver {
    repo: Arc<SadStoreRepository>,
    /// `PolicyChecker` used by the in-process `IelVerifier` walks inside
    /// `is_satisfied`. Same checker the SEL handler builds for its own
    /// `SelVerifier` — passing it here keeps the IEL-side auth check
    /// answer-equivalent to the IEL submit handler's own walk.
    checker: Arc<dyn kels_core::PolicyChecker + Send + Sync>,
    /// SEL caller's pre-walked identity_event SAIDs. Forwarded to the
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

    /// Register the SEL caller's pre-walked queried SAIDs for satisfaction
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

    /// Verify the named IEL through the shared
    /// `verify_identity_events_with_queried` helper, producing the
    /// `IelVerification` token whose `auth_policy_at` /
    /// `governance_policy_at` accessors expose the verifier-adopted
    /// policy view (NOT raw event payloads). Mirrors
    /// `AnchoredIelResolver::verification_for`.
    ///
    /// Used by `resolve_auth_policy_at` / `resolve_governance_policy_at`
    /// to honor the trust contract documented on
    /// `IelVerification::auth_policy_at`: post-divergence soft-fail
    /// Evls have their *prior* tracked policies returned, never the
    /// event's declared (unauthenticated) values. Reading
    /// `event.auth_policy` / `event.governance_policy` directly bypasses
    /// re-verification and risks trusting tampered payloads from the DB
    /// (`AGENTS.md` §Verification Invariant: "the DB cannot be trusted").
    async fn verification_for(
        &self,
        identity: &cesr::Digest256,
    ) -> Result<kels_core::IelVerification, kels_core::KelsError> {
        let source = RepositoryIelPageSource {
            repo: Arc::clone(&self.repo),
        };
        kels_core::verify_identity_events_with_queried(
            identity,
            &source,
            self.checker.clone(),
            kels_core::page_size(),
            kels_core::max_pages(),
            self.queried_saids.clone(),
        )
        .await
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
            .ok_or_else(|| kels_core::KelsError::missing_iel_event(*identity, *iel_event_said))?;
        if event.prefix != *identity {
            return Err(kels_core::KelsError::identity_binding_violation(format!(
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
        let bound = self.fetch_iel_event(identity, iel_event_said).await?;
        let verification = self.verification_for(identity).await?;
        if let Some(divergence_at) = verification.diverged_at_version()
            && bound.version >= divergence_at
        {
            return Err(kels_core::KelsError::IelDivergent(format!(
                "IEL event {} bound at version {} sits at-or-after divergence at version {}",
                iel_event_said, bound.version, divergence_at,
            )));
        }
        verification.auth_policy_at(iel_event_said).ok_or_else(|| {
            kels_core::KelsError::identity_binding_violation(format!(
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
    ) -> Result<cesr::Digest256, kels_core::KelsError> {
        let bound = self.fetch_iel_event(identity, iel_event_said).await?;
        let verification = self.verification_for(identity).await?;
        if let Some(divergence_at) = verification.diverged_at_version()
            && bound.version >= divergence_at
        {
            return Err(kels_core::KelsError::IelDivergent(format!(
                "IEL event {} bound at version {} sits at-or-after divergence at version {}",
                iel_event_said, bound.version, divergence_at,
            )));
        }
        verification
            .governance_policy_at(iel_event_said)
            .ok_or_else(|| {
                kels_core::KelsError::identity_binding_violation(format!(
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
    ) -> Result<kels_core::IelSatisfaction, kels_core::KelsError> {
        // Chain-integrity check via `fetch_iel_event`: missing-by-SAID
        // surfaces `MissingIelEvent` → re-classify into
        // `IelSatisfaction::MissingEvent` (deferrable); cross-IEL
        // contamination surfaces `IdentityBindingViolation` →
        // re-classify into `IelSatisfaction::PermanentFailure`.
        match self.fetch_iel_event(identity, said).await {
            Ok(_) => {}
            Err(kels_core::KelsError::MissingIelEvent(dep)) => {
                return Ok(kels_core::IelSatisfaction::MissingEvent {
                    iel_prefix: dep.iel_prefix,
                    event_said: dep.event_said,
                });
            }
            Err(kels_core::KelsError::IdentityBindingViolation(violation)) => {
                return Ok(kels_core::IelSatisfaction::PermanentFailure(violation));
            }
            Err(other) => return Err(other),
        }

        let mut queried = self.queried_saids.clone();
        queried.insert(*said);
        let source = RepositoryIelPageSource {
            repo: Arc::clone(&self.repo),
        };
        let verification = kels_core::verify_identity_events_with_queried(
            identity,
            &source,
            self.checker.clone(),
            kels_core::page_size(),
            kels_core::max_pages(),
            queried,
        )
        .await?;
        if verification.is_said_satisfied(said) {
            Ok(kels_core::IelSatisfaction::Satisfied)
        } else {
            Ok(kels_core::IelSatisfaction::AuthFailed {
                reason: format!(
                    "IEL event {} did not satisfy IEL verification \
                     (auth-fail or post-IEL-divergence soft) in IEL {}",
                    said, identity,
                ),
            })
        }
    }

    async fn resolve_identity_for_event(
        &self,
        iel_event_said: &cesr::Digest256,
    ) -> Result<cesr::Digest256, kels_core::KelsError> {
        let event = self
            .fetch_event_by_said(iel_event_said)
            .await?
            .ok_or_else(|| {
                // No locally-known IEL contains this event SAID. We don't
                // have an `iel_prefix` to populate `MissingIelEvent` —
                // mark as permanent here; #156's deferred-deps layer at
                // the handler will re-classify on its own when it knows
                // context.
                kels_core::KelsError::identity_binding_violation(format!(
                    "IEL event {} not found in any locally-known IEL",
                    iel_event_said,
                ))
            })?;
        Ok(event.prefix)
    }

    async fn resolve_current_auth_policy(
        &self,
        identity: &cesr::Digest256,
    ) -> Result<cesr::Digest256, kels_core::KelsError> {
        let verification = self.verification_for(identity).await?;
        if verification.is_contested() {
            return Err(kels_core::KelsError::ContestedIel(format!(
                "IEL {} is contested",
                identity,
            )));
        }
        if verification.is_decommissioned() {
            return Err(kels_core::KelsError::IelDecommissioned(format!(
                "IEL {} is decommissioned",
                identity,
            )));
        }
        if verification.is_divergent() {
            return Err(kels_core::KelsError::IelDivergent(format!(
                "IEL {} is divergent — no canonical current auth_policy",
                identity,
            )));
        }
        let tip = verification.current_event().ok_or_else(|| {
            kels_core::KelsError::NotFound(format!(
                "IEL {} has no current event — chain not locally known",
                identity,
            ))
        })?;
        verification.auth_policy_at(&tip.said).ok_or_else(|| {
            kels_core::KelsError::InvalidIel(format!(
                "IEL {} tip event {} has no auth_policy in policy_history \
                 (chain integrity breach)",
                identity, tip.said,
            ))
        })
    }

    async fn iel_chain_positions(
        &self,
        identity: &cesr::Digest256,
        saids: &[cesr::Digest256],
    ) -> Result<kels_core::IelChainPositionBatch, kels_core::KelsError> {
        if saids.is_empty() {
            return Ok(kels_core::IelChainPositionBatch {
                found: Vec::new(),
                missing: Vec::new(),
            });
        }

        // Dedup input per the partial-results contract.
        let mut deduped: Vec<cesr::Digest256> = saids.to_vec();
        deduped.sort();
        deduped.dedup();

        // Resolving-category read: see
        // `docs/design/streaming-verification-architecture.md §Operation
        // Categories`. A wrong answer here causes the SEL walker's
        // monotonic ratchet to compare positions by version-only; the
        // actual auth boundary is `is_satisfied` (which runs the full IEL
        // verifier walk) — a tampered `first_divergent_version` is caught
        // there, not here. Cross-primitive asymmetry with the client-side
        // `AnchoredIelResolver::iel_chain_positions` is design-by-intent
        // per slice 7 Decision 3.
        let divergent_at = self
            .repo
            .iel_events
            .first_divergent_version(identity)
            .await
            .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))?;

        // For non-divergent IELs the walk-back never fires, so we keep
        // the per-SAID lookup path. For divergent IELs we materialize the
        // full chain into a map once and feed it to the shared walker —
        // each post-divergence SAID resolves its branch identity in
        // O(divergent-depth) hashmap hops with no extra DB queries.
        let chain_map = if divergent_at.is_some() {
            Some(self.materialize_iel_chain(identity).await?)
        } else {
            None
        };

        let mut found: Vec<kels_core::IelChainPosition> = Vec::new();
        let mut missing: Vec<cesr::Digest256> = Vec::new();
        for said in &deduped {
            // Per-SAID fetch swallows `MissingIelEvent` into the `missing`
            // bucket; `IdentityBindingViolation` (cross-IEL contamination)
            // and other errors propagate as-is.
            let event = match self.fetch_iel_event(identity, said).await {
                Ok(e) => e,
                Err(kels_core::KelsError::MissingIelEvent(_)) => {
                    missing.push(*said);
                    continue;
                }
                Err(other) => return Err(other),
            };
            let branch_marker = match (divergent_at, chain_map.as_ref()) {
                (Some(d), Some(chain)) if event.version >= d => Some(
                    kels_core::walk_back_to_branch_identity(chain, *said, d, identity)?,
                ),
                _ => None,
            };
            found.push(kels_core::IelChainPosition {
                version: event.version,
                kind: event.kind,
                said: *said,
                branch_marker,
            });
        }
        Ok(kels_core::IelChainPositionBatch { found, missing })
    }
}

impl RepositoryIelResolver {
    /// Materialize every event in the named IEL into a `said → event` map
    /// via the IEL repository pool. Mirrors `AnchoredIelResolver::collect_all_events`
    /// for the in-process path. Used by `iel_chain_positions`'s walk-back
    /// to determine post-divergence branch identity. Bounded by
    /// `max_pages`; fail-secure on overrun (so the walker never sees an
    /// incomplete chain).
    async fn materialize_iel_chain(
        &self,
        identity: &cesr::Digest256,
    ) -> Result<
        std::collections::HashMap<cesr::Digest256, kels_core::IdentityEvent>,
        kels_core::KelsError,
    > {
        let mut found: std::collections::HashMap<cesr::Digest256, kels_core::IdentityEvent> =
            std::collections::HashMap::new();
        let prefix_str = identity.to_string();
        let page_size = kels_core::page_size() as u64;
        let max_pages = kels_core::max_pages();
        let mut since: Option<String> = None;
        let mut exhausted = false;
        for _ in 0..max_pages {
            let events = self
                .repo
                .iel_events
                .fetch_iel_page_pool(
                    crate::repository::IelChainSelector::Prefix(&prefix_str),
                    since.as_deref(),
                    Some(page_size),
                )
                .await
                .map_err(|e| kels_core::KelsError::StorageError(e.to_string()))?;
            if events.is_empty() {
                exhausted = true;
                break;
            }
            since = events.last().map(|e| e.said.to_string());
            for event in &events {
                if event.prefix != *identity {
                    return Err(kels_core::KelsError::identity_binding_violation(format!(
                        "IEL event {} has prefix {} but expected identity {} \
                         (cross-IEL contamination)",
                        event.said, event.prefix, identity,
                    )));
                }
                found.insert(event.said, event.clone());
            }
            // A short page guarantees end-of-chain (post-filtered to
            // strict-gt semantics in `fetch_iel_page_pool`).
            if (events.len() as u64) < page_size {
                exhausted = true;
                break;
            }
        }
        if !exhausted {
            return Err(kels_core::KelsError::InvalidIel(format!(
                "IEL walk-back materialization exceeded max_pages limit ({}) for {}",
                max_pages, identity,
            )));
        }
        Ok(found)
    }
}
