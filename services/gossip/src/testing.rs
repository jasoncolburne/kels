//! Test fixtures shared across the gossip service's test suites.
//!
//! Currently hosts [`FederationFixture`] — an in-memory federation IEL
//! Icp with N member peers, each with a `peer/services` SEL chain
//! staged in an `InMemorySadStore` cascade and an evaluator wired to
//! in-memory policy/iel resolvers. Consumed by:
//!
//! - `address_resolver::tests` — `FederationAddressResolver` end-to-end
//!   tests against the fixture.
//! - `sync::tests` — federation IEL re-walk + `RetainPeers` trigger
//!   tests.
//!
//! Fixture size note: `compute_federation_governance_threshold(n)`
//! clamps to 3 for `n ∈ [0, 5]` (protects small federations from
//! trivial collusion). The policy DSL rejects `threshold(M, [children])`
//! when `M > len(children)`, so the smallest constructible federation
//! shape uses 3 members.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use cesr::Digest256;

use kels_core::{
    AnchorEvaluation, IdentityEvent, IdentityEventKind, IelChainPosition, IelChainPositionBatch,
    IelResolver, IelSatisfaction, InMemorySadStore, KelsError, PEER_SERVICES_SEL_TOPIC,
    PagedIelSource, PeerServicesSad, PolicyChecker, SadEvent, SadStore,
    compute_federation_governance_threshold,
};
use kels_policy::{InMemoryPolicyResolver, Policy, PolicyResolver};

use crate::authorization::FederationEvaluator;

/// Test fixture: a federation IEL Icp with N member peers, each
/// optionally with a `peer/services` SEL chain landed in the cascade.
///
/// Federation auth/governance policies conform to the federation shape
/// (`any(iel(...))` + `threshold(M, [iel(...)])` over the same member
/// set, both immune).
pub(crate) struct FederationFixture {
    pub(crate) federation_iel_prefix: Digest256,
    pub(crate) members: Vec<MemberFixture>,
    pub(crate) evaluator: Arc<FederationEvaluator>,
    pub(crate) cascade: Arc<dyn SadStore>,
}

pub(crate) struct MemberFixture {
    pub(crate) iel_prefix: Digest256,
    #[allow(dead_code)]
    pub(crate) domain: String,
}

impl FederationFixture {
    /// Build a fixture with the given member specs. Each entry is
    /// `(label, domain)`. All members get a peer/services chain staged.
    pub(crate) async fn new(specs: &[(&str, &str)]) -> Self {
        let specs_with_chains: Vec<(&str, Option<&str>)> =
            specs.iter().map(|(l, d)| (*l, Some(*d))).collect();
        Self::new_partial(&specs_with_chains).await
    }

    /// Like [`Self::new`], but each member's `domain` is `Option` —
    /// `None` means the federation knows about this member but their
    /// `peer/services` chain hasn't propagated yet.
    pub(crate) async fn new_partial(specs: &[(&str, Option<&str>)]) -> Self {
        let cascade: Arc<dyn SadStore> = Arc::new(InMemorySadStore::new());

        let mut members = Vec::new();
        let mut policies = Vec::new();
        let mut iel_events: BTreeMap<Digest256, (u64, IdentityEventKind, Digest256, Digest256)> =
            BTreeMap::new();
        let mut current_auth_for: BTreeMap<Digest256, Digest256> = BTreeMap::new();

        for (label, domain_opt) in specs {
            let iel_prefix = blake3_label(&format!("iel-{label}"));
            let kel_prefix = blake3_label(&format!("kel-{label}"));
            let member_policy = Policy::build(&format!("kel({kel_prefix})"), None, true).unwrap();
            current_auth_for.insert(iel_prefix, member_policy.said);
            policies.push(member_policy);

            let domain_owned = if let Some(domain) = domain_opt {
                let iel_event_said =
                    stage_member_services_chain(cascade.as_ref(), iel_prefix, domain).await;
                let auth_at = blake3_label(&format!("auth-policy-{label}"));
                let gov_at = blake3_label(&format!("gov-policy-{label}"));
                iel_events.insert(iel_event_said, (0, IdentityEventKind::Icp, auth_at, gov_at));
                domain.to_string()
            } else {
                String::new()
            };

            members.push(MemberFixture {
                iel_prefix,
                domain: domain_owned,
            });
        }

        // Federation `(auth_policy, governance_policy)` over the member
        // set — `any(iel(...))` + `threshold(M, [iel(...)])`.
        let member_iels: Vec<Digest256> = members.iter().map(|m| m.iel_prefix).collect();
        let (fed_auth, fed_gov) = build_federation_policies(&member_iels);

        let fed_icp =
            IdentityEvent::icp(fed_auth.said, fed_gov.said, "kels/iel/v1/federation").unwrap();
        let federation_iel_prefix = fed_icp.prefix;
        let fed_tip_said = fed_icp.said;
        current_auth_for.insert(federation_iel_prefix, fed_auth.said);
        iel_events.insert(
            fed_tip_said,
            (0, IdentityEventKind::Icp, fed_auth.said, fed_gov.said),
        );
        policies.push(fed_auth);
        policies.push(fed_gov);

        let evaluator = build_evaluator(policies, iel_events, current_auth_for, federation_iel_prefix, vec![fed_icp]);

        Self {
            federation_iel_prefix,
            members,
            evaluator,
            cascade,
        }
    }
}

/// Build the federation `(auth_policy, governance_policy)` pair for the
/// given member IEL prefix set.
pub(crate) fn build_federation_policies(members: &[Digest256]) -> (Policy, Policy) {
    let auth_expr = format!(
        "any({})",
        members
            .iter()
            .map(|p| format!("iel({p})"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    let m_threshold = compute_federation_governance_threshold(members.len());
    let gov_expr = format!(
        "threshold({m_threshold}, [{}])",
        members
            .iter()
            .map(|p| format!("iel({p})"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    let fed_auth = Policy::build(&auth_expr, None, true).unwrap();
    let fed_gov = Policy::build(&gov_expr, None, true).unwrap();
    (fed_auth, fed_gov)
}

/// Build the federation evaluator with the given pre-populated policy +
/// IEL resolver state and the federation IEL chain.
fn build_evaluator(
    policies: Vec<Policy>,
    iel_events: BTreeMap<Digest256, (u64, IdentityEventKind, Digest256, Digest256)>,
    current_auth_for: BTreeMap<Digest256, Digest256>,
    federation_iel_prefix: Digest256,
    federation_chain: Vec<IdentityEvent>,
) -> Arc<FederationEvaluator> {
    let policy_resolver: Arc<dyn PolicyResolver + Send + Sync> =
        Arc::new(InMemoryPolicyResolver::new(policies));
    let iel_resolver: Arc<dyn IelResolver + Send + Sync> = Arc::new(InMemoryIelResolverFixture {
        events: iel_events,
        current_auth_for,
    });
    let iel_aware_checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::new(AlwaysPassChecker);
    let iel_source: Arc<dyn PagedIelSource + Send + Sync> = Arc::new(InMemoryPagedIelSource {
        chain: vec![(federation_iel_prefix, federation_chain)]
            .into_iter()
            .collect(),
    });
    Arc::new(FederationEvaluator {
        policy_resolver,
        iel_resolver,
        iel_aware_checker,
        iel_source,
    })
}

pub(crate) fn blake3_label(s: &str) -> Digest256 {
    Digest256::blake3_256(s.as_bytes())
}

/// Stage a `[Icp, Upd, Sea]` peer/services chain for one member +
/// cache the published `PeerServicesSad` body. Returns the synthetic
/// IEL event SAID the Upd/Sea events bind to.
pub(crate) async fn stage_member_services_chain(
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

pub(crate) struct AlwaysPassChecker;

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

/// Multi-identity `IelResolver` keyed by event SAID + identity prefix.
pub(crate) struct InMemoryIelResolverFixture {
    pub(crate) events: BTreeMap<Digest256, (u64, IdentityEventKind, Digest256, Digest256)>,
    pub(crate) current_auth_for: BTreeMap<Digest256, Digest256>,
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

/// Simple in-memory `PagedIelSource` keyed by prefix.
pub(crate) struct InMemoryPagedIelSource {
    pub(crate) chain: BTreeMap<Digest256, Vec<IdentityEvent>>,
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
