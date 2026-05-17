//! Federation-aware [`AddressResolver`] for gossip.
//!
//! Enumerates the federation IEL's current `authPolicy` member set on every
//! call, walks each peer's `peer/services` chain through the local sadstore,
//! and returns the published base domain. The local node's identity is
//! excluded from results — gossip never broadcasts to itself.
//!
//! Fresh walks per call (no cross-decision cache); URL lookup is an
//! addressing concern, not a chain-state security decision, but the
//! federation walk itself runs DVTI-fresh per the same rule that governs
//! `is_peer_authorized` (`authorization.rs` module docs).

use std::sync::Arc;

use async_trait::async_trait;
use cesr::Digest256;
use tracing::debug;

use kels_core::{
    AddressResolver, KelsError, SadStore, resolve_peer_services_domain,
};

use crate::authorization::{FederationEvaluator, walk_federation_iel};

/// Federation-aware resolver. Each lookup walks the federation IEL fresh,
/// enumerates members, and resolves their `peer/services` publications.
pub struct FederationAddressResolver {
    federation_iel_prefix: Digest256,
    evaluator: Arc<FederationEvaluator>,
    cascade: Arc<dyn SadStore>,
    local_identity: Option<Digest256>,
}

impl FederationAddressResolver {
    pub fn new(
        federation_iel_prefix: Digest256,
        evaluator: Arc<FederationEvaluator>,
        cascade: Arc<dyn SadStore>,
        local_identity: Option<Digest256>,
    ) -> Self {
        Self {
            federation_iel_prefix,
            evaluator,
            cascade,
            local_identity,
        }
    }

    async fn current_members(&self) -> Result<Vec<Digest256>, KelsError> {
        let state =
            walk_federation_iel(&self.federation_iel_prefix, self.evaluator.as_ref())
                .await
                .map_err(|e| KelsError::StorageError(format!("federation walk: {e}")))?;
        Ok(state.members.into_iter().collect())
    }
}

#[async_trait]
impl AddressResolver for FederationAddressResolver {
    async fn resolve_domain(
        &self,
        peer_identity: &Digest256,
    ) -> Result<Option<String>, KelsError> {
        if Some(*peer_identity) == self.local_identity {
            return Ok(None);
        }
        let members = self.current_members().await?;
        if !members.contains(peer_identity) {
            debug!(peer = %peer_identity, "address-resolver: peer not in current federation authPolicy");
            return Ok(None);
        }
        resolve_peer_services_domain(
            *peer_identity,
            self.cascade.as_ref(),
            Arc::clone(&self.evaluator.iel_aware_checker),
            Arc::clone(&self.evaluator.iel_resolver),
        )
        .await
    }

    async fn list_domains(&self) -> Result<Vec<(Digest256, String)>, KelsError> {
        let members = self.current_members().await?;
        let mut out = Vec::new();
        for peer in members {
            if Some(peer) == self.local_identity {
                continue;
            }
            match resolve_peer_services_domain(
                peer,
                self.cascade.as_ref(),
                Arc::clone(&self.evaluator.iel_aware_checker),
                Arc::clone(&self.evaluator.iel_resolver),
            )
            .await
            {
                Ok(Some(domain)) => out.push((peer, domain)),
                Ok(None) => {
                    debug!(peer = %peer, "address-resolver: peer/services not yet resolvable; skipping");
                }
                Err(e) => {
                    // Per-peer resolution failure (e.g., Upd-tailed chain)
                    // shouldn't abort the whole listing. Log + skip; the
                    // next refresh tries again.
                    debug!(peer = %peer, error = %e, "address-resolver: peer/services resolution errored; skipping");
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::BTreeMap;

    use kels_core::{
        AnchorEvaluation, IdentityEvent, IdentityEventKind, IelChainPosition,
        IelChainPositionBatch, IelResolver, IelSatisfaction, InMemorySadStore, KelsError,
        PEER_SERVICES_SEL_TOPIC, PagedIelSource, PeerServicesSad, PolicyChecker, SadEvent,
        compute_federation_governance_threshold,
    };
    use kels_policy::{InMemoryPolicyResolver, Policy, PolicyResolver};

    /// Test fixture: a federation IEL Icp with N member peers, each with a
    /// `peer/services` SEL chain landed in the cascade. The federation
    /// auth/governance policies conform to the federation shape
    /// (`any(iel(...))` + `threshold(M, [iel(...)])` over the same member
    /// set, both immune).
    ///
    /// Reusable for Gap 9's federation-IEL-event-driven-teardown tests
    /// (which will synthesize subsequent Evl events through the same
    /// in-memory source).
    struct FederationFixture {
        federation_iel_prefix: Digest256,
        members: Vec<MemberFixture>,
        evaluator: Arc<FederationEvaluator>,
        cascade: Arc<dyn SadStore>,
    }

    struct MemberFixture {
        iel_prefix: Digest256,
        #[allow(dead_code)]
        domain: String,
    }

    impl FederationFixture {
        /// Build a fixture with the given member specs. Each entry is
        /// `(label, domain)` — `label` is used to derive a deterministic
        /// IEL prefix (`blake3("iel-{label}")`), and `domain` is the
        /// published base domain in that member's peer/services SAD. All
        /// members get a peer/services chain staged in the cascade.
        async fn new(specs: &[(&str, &str)]) -> Self {
            let specs_with_chains: Vec<(&str, Option<&str>)> =
                specs.iter().map(|(l, d)| (*l, Some(*d))).collect();
            Self::new_partial(&specs_with_chains).await
        }

        /// Like [`new`], but each member's `domain` is `Option` — `None`
        /// means the federation knows about this member but their
        /// `peer/services` chain hasn't propagated yet (or never will).
        /// Used to exercise the resolver's best-effort behavior under
        /// partial cascade state.
        async fn new_partial(specs: &[(&str, Option<&str>)]) -> Self {
            let cascade: Arc<dyn SadStore> = Arc::new(InMemorySadStore::new());

            // Build member fixtures + per-member sub-policies (`kel(K_i)`)
            // + iel_resolver entries for both the member's IEL event SAID
            // (consumed by SEL Upd events) and the federation's tip event.
            let mut members = Vec::new();
            let mut policies = Vec::new();
            // (event_said) -> (version, kind, auth_policy_said, governance_policy_said)
            let mut iel_events: BTreeMap<
                Digest256,
                (u64, IdentityEventKind, Digest256, Digest256),
            > = BTreeMap::new();
            // identity → policy_said for `resolve_current_auth_policy`.
            let mut current_auth_for: BTreeMap<Digest256, Digest256> = BTreeMap::new();

            for (label, domain_opt) in specs {
                let iel_prefix = blake3_label(&format!("iel-{label}"));
                let kel_prefix = blake3_label(&format!("kel-{label}"));
                let member_policy =
                    Policy::build(&format!("kel({kel_prefix})"), None, true).unwrap();
                current_auth_for.insert(iel_prefix, member_policy.said);
                policies.push(member_policy);

                // Stage the peer/services SEL [Icp, Upd, Sea] + body in
                // the cascade when a domain is given. The Upd events bind
                // to a synthetic IEL event SAID; the iel_resolver below
                // knows about it so SEL verification
                // (resolve_auth_policy_at) succeeds. When `domain_opt`
                // is None, the chain is left unstaged — the resolver
                // surfaces `Ok(None)` for that member.
                let domain_owned = if let Some(domain) = domain_opt {
                    let iel_event_said = stage_member_services_chain(
                        cascade.as_ref(),
                        iel_prefix,
                        domain,
                    )
                    .await;
                    let auth_at = blake3_label(&format!("auth-policy-{label}"));
                    let gov_at = blake3_label(&format!("gov-policy-{label}"));
                    iel_events.insert(
                        iel_event_said,
                        (0, IdentityEventKind::Icp, auth_at, gov_at),
                    );
                    domain.to_string()
                } else {
                    String::new()
                };

                members.push(MemberFixture {
                    iel_prefix,
                    domain: domain_owned,
                });
            }

            // Federation auth_policy = `any(iel(M_1), ..., iel(M_n))`.
            // Federation governance_policy = `threshold(M, [iel(M_i)...])`
            // where M = compute_federation_governance_threshold(n). Both
            // immune per the federation policy shape rule.
            let member_iels: Vec<Digest256> = members.iter().map(|m| m.iel_prefix).collect();
            let n = member_iels.len();
            let auth_expr = format!(
                "any({})",
                member_iels
                    .iter()
                    .map(|p| format!("iel({p})"))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            let m_threshold = compute_federation_governance_threshold(n);
            let gov_expr = format!(
                "threshold({m_threshold}, [{}])",
                member_iels
                    .iter()
                    .map(|p| format!("iel({p})"))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            let fed_auth = Policy::build(&auth_expr, None, true).unwrap();
            let fed_gov = Policy::build(&gov_expr, None, true).unwrap();

            // Federation Icp event. Prefix is derived from
            // (auth, gov, topic) by `IdentityEvent::icp`.
            let fed_icp = IdentityEvent::icp(
                fed_auth.said,
                fed_gov.said,
                "kels/iel/v1/federation",
            )
            .unwrap();
            let federation_iel_prefix = fed_icp.prefix;
            let fed_tip_said = fed_icp.said;
            current_auth_for.insert(federation_iel_prefix, fed_auth.said);
            iel_events.insert(
                fed_tip_said,
                (0, IdentityEventKind::Icp, fed_auth.said, fed_gov.said),
            );
            policies.push(fed_auth);
            policies.push(fed_gov);

            // Wire up the evaluator: in-memory policy resolver, in-memory
            // iel resolver (knows about every SEL-bound IEL event), an
            // always-pass policy checker (immune policies bypass anchor
            // checks anyway), and an in-memory federation IEL source.
            let policy_resolver: Arc<dyn PolicyResolver + Send + Sync> =
                Arc::new(InMemoryPolicyResolver::new(policies));
            let iel_resolver: Arc<dyn IelResolver + Send + Sync> =
                Arc::new(InMemoryIelResolverFixture {
                    events: iel_events,
                    current_auth_for,
                });
            let iel_aware_checker: Arc<dyn PolicyChecker + Send + Sync> =
                Arc::new(AlwaysPassChecker);
            let iel_source: Arc<dyn PagedIelSource + Send + Sync> =
                Arc::new(InMemoryPagedIelSource {
                    chain: vec![(federation_iel_prefix, vec![fed_icp])]
                        .into_iter()
                        .collect(),
                });

            let evaluator = Arc::new(FederationEvaluator {
                policy_resolver,
                iel_resolver,
                iel_aware_checker,
                iel_source,
            });

            Self {
                federation_iel_prefix,
                members,
                evaluator,
                cascade,
            }
        }

    }

    fn blake3_label(s: &str) -> Digest256 {
        cesr::Digest256::blake3_256(s.as_bytes())
    }

    /// Stage a `[Icp, Upd, Sea]` peer/services chain for one member +
    /// cache the published `PeerServicesSad` body. Returns the synthetic
    /// IEL event SAID the Upd/Sea events bind to.
    async fn stage_member_services_chain(
        cascade: &dyn SadStore,
        member_iel: Digest256,
        domain: &str,
    ) -> Digest256 {
        let iel_event_said = blake3_label(&format!("iel-event-for-{member_iel}"));
        let sad = PeerServicesSad::create(domain.to_string()).unwrap();
        cascade
            .store(&sad.said, &serde_json::to_value(&sad).unwrap())
            .await
            .unwrap();
        let icp = SadEvent::icp(member_iel, PEER_SERVICES_SEL_TOPIC).unwrap();
        let upd = SadEvent::upd(&icp, iel_event_said, sad.said).unwrap();
        let sea = SadEvent::sea(&upd, iel_event_said).unwrap();
        cascade.store_sel_event(&icp).await.unwrap();
        cascade.store_sel_event(&upd).await.unwrap();
        cascade.store_sel_event(&sea).await.unwrap();
        iel_event_said
    }

    struct AlwaysPassChecker;

    #[async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn evaluate(
            &self,
            _: &Digest256,
            _: &Digest256,
        ) -> Result<AnchorEvaluation, KelsError> {
            Ok(AnchorEvaluation {
                satisfied: true,
                missing_anchors: Vec::new(),
            })
        }
        async fn is_immune(&self, _: &Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    /// Multi-identity `IelResolver`: knows about every IEL event SAID
    /// (federation + each member's SEL-bound stub event) and answers
    /// `resolve_auth_policy_at` / `resolve_current_auth_policy` from
    /// pre-populated maps. Mirrors the kels_core test pattern but
    /// generalizes the single-identity restriction.
    struct InMemoryIelResolverFixture {
        events: BTreeMap<Digest256, (u64, IdentityEventKind, Digest256, Digest256)>,
        current_auth_for: BTreeMap<Digest256, Digest256>,
    }

    #[async_trait]
    impl IelResolver for InMemoryIelResolverFixture {
        async fn fetch_iel_event(
            &self,
            _: &Digest256,
            said: &Digest256,
        ) -> Result<IdentityEvent, KelsError> {
            let (version, kind, auth, gov) = self
                .events
                .get(said)
                .copied()
                .ok_or_else(|| KelsError::NotFound(format!("iel event {}", said)))?;
            let mut event = IdentityEvent::icp(auth, gov, "kels/iel/v1/test")?;
            event.version = version;
            event.kind = kind;
            event.said = *said;
            Ok(event)
        }
        async fn resolve_auth_policy_at(
            &self,
            _: &Digest256,
            said: &Digest256,
        ) -> Result<Digest256, KelsError> {
            self.events
                .get(said)
                .map(|(_, _, auth, _)| *auth)
                .ok_or_else(|| KelsError::NotFound(format!("auth at {}", said)))
        }
        async fn resolve_governance_policy_at(
            &self,
            _: &Digest256,
            said: &Digest256,
        ) -> Result<Digest256, KelsError> {
            self.events
                .get(said)
                .map(|(_, _, _, gov)| *gov)
                .ok_or_else(|| KelsError::NotFound(format!("gov at {}", said)))
        }
        async fn iel_chain_positions(
            &self,
            _: &Digest256,
            saids: &[Digest256],
        ) -> Result<IelChainPositionBatch, KelsError> {
            let mut found = Vec::new();
            let mut missing = Vec::new();
            for said in saids {
                if let Some((version, kind, _, _)) = self.events.get(said).copied() {
                    found.push(IelChainPosition {
                        version,
                        kind,
                        said: *said,
                        branch_marker: None,
                    });
                } else {
                    missing.push(*said);
                }
            }
            Ok(IelChainPositionBatch { found, missing })
        }
        async fn is_satisfied(
            &self,
            _: &Digest256,
            _: &Digest256,
        ) -> Result<IelSatisfaction, KelsError> {
            Ok(IelSatisfaction::Satisfied)
        }
        async fn resolve_identity_for_event(
            &self,
            _: &Digest256,
        ) -> Result<Digest256, KelsError> {
            Err(KelsError::NotFound(
                "resolve_identity_for_event not exercised by these tests".into(),
            ))
        }
        async fn resolve_current_auth_policy(
            &self,
            identity: &Digest256,
        ) -> Result<Digest256, KelsError> {
            self.current_auth_for
                .get(identity)
                .copied()
                .ok_or_else(|| KelsError::NotFound(format!("auth for {}", identity)))
        }
    }

    /// Simple in-memory `PagedIelSource` keyed by prefix. Returns the
    /// stored event list for known prefixes; empty page otherwise.
    struct InMemoryPagedIelSource {
        chain: BTreeMap<Digest256, Vec<IdentityEvent>>,
    }

    #[async_trait]
    impl PagedIelSource for InMemoryPagedIelSource {
        async fn fetch_page(
            &self,
            prefix: &Digest256,
            since: Option<&Digest256>,
            _limit: usize,
        ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
            let Some(events) = self.chain.get(prefix) else {
                return Ok((Vec::new(), false));
            };
            // Single-page semantics: if cursor is None return all; if cursor
            // is Some, return the slice after the cursor's event.
            match since {
                None => Ok((events.clone(), false)),
                Some(cursor) => {
                    let after = events
                        .iter()
                        .position(|e| e.said == *cursor)
                        .map(|i| i + 1)
                        .unwrap_or(events.len());
                    Ok((events.iter().skip(after).cloned().collect(), false))
                }
            }
        }
    }

    // ==================== Tests ====================

    // ----- Test fixture sizing note -----
    //
    // `compute_federation_governance_threshold(n)` clamps to 3 for
    // `n ∈ [0, 5]` (protects small federations from trivial collusion;
    // see `docs/design/infrastructure/federation.md §Threshold formula`).
    // The policy-DSL parser rejects `threshold(M, [children])` when
    // `M > len(children)`, so the smallest constructible federation
    // shape uses 3 members.

    #[tokio::test]
    async fn federation_resolver_returns_published_domain_for_member() {
        let fixture = FederationFixture::new(&[
            ("alice", "alice.example.net"),
            ("bob", "bob.example.net"),
            ("charlie", "charlie.example.net"),
        ])
        .await;

        let resolver = FederationAddressResolver::new(
            fixture.federation_iel_prefix,
            Arc::clone(&fixture.evaluator),
            Arc::clone(&fixture.cascade),
            None,
        );

        let alice = fixture.members[0].iel_prefix;
        assert_eq!(
            resolver.resolve_domain(&alice).await.unwrap(),
            Some("alice.example.net".to_string()),
        );
    }

    #[tokio::test]
    async fn federation_resolver_returns_none_for_non_member() {
        let fixture = FederationFixture::new(&[
            ("alice", "alice.example.net"),
            ("bob", "bob.example.net"),
            ("charlie", "charlie.example.net"),
        ])
        .await;

        let resolver = FederationAddressResolver::new(
            fixture.federation_iel_prefix,
            Arc::clone(&fixture.evaluator),
            Arc::clone(&fixture.cascade),
            None,
        );

        let stranger = blake3_label("iel-stranger");
        assert_eq!(resolver.resolve_domain(&stranger).await.unwrap(), None);
    }

    #[tokio::test]
    async fn federation_resolver_excludes_local_identity_from_list() {
        let fixture = FederationFixture::new(&[
            ("alice", "alice.example.net"),
            ("bob", "bob.example.net"),
            ("charlie", "charlie.example.net"),
        ])
        .await;
        let local = fixture.members[0].iel_prefix;
        let bob_iel = fixture.members[1].iel_prefix;
        let charlie_iel = fixture.members[2].iel_prefix;

        let resolver = FederationAddressResolver::new(
            fixture.federation_iel_prefix,
            Arc::clone(&fixture.evaluator),
            Arc::clone(&fixture.cascade),
            Some(local),
        );

        let mut list = resolver.list_domains().await.unwrap();
        list.sort_by_key(|(iel, _)| *iel);
        let mut expected: Vec<(Digest256, String)> = vec![
            (bob_iel, "bob.example.net".to_string()),
            (charlie_iel, "charlie.example.net".to_string()),
        ];
        expected.sort_by_key(|(iel, _)| *iel);
        assert_eq!(list, expected, "self excluded; other members surfaced");

        // Direct self-lookup also short-circuits to None.
        assert_eq!(resolver.resolve_domain(&local).await.unwrap(), None);
    }

    #[tokio::test]
    async fn federation_resolver_list_skips_unresolvable_member() {
        // Federation has three members, but Charlie's peer/services
        // chain hasn't propagated locally yet (cold-start / gossip-lag).
        // `list_domains` should surface the two resolvable members and
        // skip the third — one unresolvable peer doesn't abort the walk.
        let fixture = FederationFixture::new_partial(&[
            ("alice", Some("alice.example.net")),
            ("bob", Some("bob.example.net")),
            ("charlie", None),
        ])
        .await;

        let resolver = FederationAddressResolver::new(
            fixture.federation_iel_prefix,
            Arc::clone(&fixture.evaluator),
            Arc::clone(&fixture.cascade),
            None,
        );

        let mut list = resolver.list_domains().await.unwrap();
        list.sort_by_key(|(iel, _)| *iel);
        let mut expected: Vec<(Digest256, String)> = vec![
            (fixture.members[0].iel_prefix, "alice.example.net".to_string()),
            (fixture.members[1].iel_prefix, "bob.example.net".to_string()),
        ];
        expected.sort_by_key(|(iel, _)| *iel);
        assert_eq!(list, expected);
    }
}
