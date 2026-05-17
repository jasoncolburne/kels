// Walker primitives. Today `FederationAddressResolver` resolves URLs via
// `kels_core::resolve_peer_services_domain` directly, so these walkers are
// only exercised by their own unit tests; the `peer/gossip` walker waits
// on the federation-gated `host:port` consumption surface. Suppressed
// dead-code module-wide until those callsites land.
#![allow(dead_code)]

//! Per-peer discovery: federation `authPolicy` → per-peer SEL chains →
//! published SAD bodies.
//!
//! Two parallel walkers — one per chain — plus a composite that returns
//! both halves for federation members:
//!
//! - [`walk_peer_services`] — public `peer/services` chain; returns
//!   [`PeerServicesSad`] per member. End-user clients call only this one
//!   (no federation membership required).
//! - [`walk_peer_gossip`] — federation-gated `peer/gossip` chain; returns
//!   [`PeerGossipSad`] per member. Body fetch requires a `SignedRequest`
//!   under the peer's `readPolicy` (federation-only).
//! - [`walk_federation_peers`] — composes both for federation members.
//!
//! Each walker reads chain events via the supplied cascade
//! (typically `CascadingSadStore[RepositorySadStore, RemoteSadStore]`),
//! verifies the chain via [`sel_completed_verification`] using the
//! evaluator's policy checker and IEL resolver, rejects Upd-tailed tips
//! per the federation address-SEL convention, and fetches the SAD body
//! at the tip's `content` SAID via `cascade.load`.
//!
//! Per-peer failures are surfaced as [`UnresolvedPeer`] entries rather than
//! aborting the whole walk. A single peer's missing chain (cold start /
//! gossip lag) or unfetchable body must not block discovery for the rest of
//! the membership; anti-entropy fills the gaps on the next pass (see
//! discovery.md §Failure modes).

use std::{collections::BTreeMap, sync::Arc};

use cesr::Digest256;
use thiserror::Error;
use tracing::{debug, warn};

use kels_core::{
    KelsError, PeerGossipSad, PeerServicesSad, SadEvent, SadEventKind, SadStore, SadStorePageLoader,
    compute_peer_gossip_sel_prefix, compute_peer_services_sel_prefix, sel_completed_verification,
};

use crate::authorization::{FederationEvaluator, FederationState};

/// Which chain a walk targeted, surfaced on per-peer failures for
/// operator-readable error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Services,
    Gossip,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Services => f.write_str("peer/services"),
            Chain::Gossip => f.write_str("peer/gossip"),
        }
    }
}

/// Result of walking one peer-SEL chain across every member of the
/// federation's `authPolicy`. Generic over the published SAD body type so
/// both `peer/services` and `peer/gossip` use the same shape.
#[derive(Debug)]
pub struct PeerChainDiscovery<S> {
    /// Members whose chain was verified and whose published SAD body was
    /// fetched. Iterate this map to consume resolved publications.
    pub resolved: BTreeMap<Digest256, S>,
    /// Members whose chain or body was unreachable / malformed when this
    /// walk ran. Logged for operator visibility; not a fatal condition —
    /// anti-entropy fills the gaps on the next pass.
    pub unresolved: Vec<UnresolvedPeer>,
}

impl<S> Default for PeerChainDiscovery<S> {
    fn default() -> Self {
        Self {
            resolved: BTreeMap::new(),
            unresolved: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct UnresolvedPeer {
    pub identity: Digest256,
    pub chain: Chain,
    pub reason: DiscoveryError,
}

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("failed to derive {chain} SEL prefix for peer {peer}: {source}")]
    PrefixDerive {
        peer: Digest256,
        chain: Chain,
        #[source]
        source: KelsError,
    },
    #[error("{chain} chain verification failed for peer {peer}: {source}")]
    ChainVerification {
        peer: Digest256,
        chain: Chain,
        #[source]
        source: KelsError,
    },
    /// Chain tip is an `Upd` rather than a trailing `Sea`. Per the
    /// federation per-peer SEL convention (see `peer-identity.md §HSM
    /// ceremony step 4` and `protocol-doctrine.md §Sea-after-Upd ratchet`),
    /// conforming tooling never emits an Upd-tailed chain; reject the chain
    /// rather than treating a pre-seal Upd as the current publication.
    #[error(
        "{chain} for peer {peer} has unsealed tip {tip_kind}; conforming tooling never produces \
         an Upd-tailed per-peer SEL"
    )]
    UpdTailedChain {
        peer: Digest256,
        chain: Chain,
        tip_kind: SadEventKind,
    },
    /// Verifier returned no current event — peer's chain is empty or
    /// unreachable in the cascade (typical during cold start / gossip lag).
    #[error("{chain} for peer {peer} has no current event yet")]
    NoTip { peer: Digest256, chain: Chain },
    /// Tip event is `Sea` but its preserved `content` field is `None`.
    /// Structurally impossible under the convention (Sea preserves the
    /// Upd's content), but surfaced explicitly so a server bug or
    /// malformed event doesn't silently pass through.
    #[error("{chain} tip for peer {peer} has no content SAID")]
    TipNoContent { peer: Digest256, chain: Chain },
    /// SAD body for the tip's content SAID isn't fetchable. Either the
    /// body hasn't propagated yet (cold start) or the cache + remote both
    /// miss.
    #[error("{chain} SAD body {said} not found for peer {peer}")]
    BodyMissing {
        peer: Digest256,
        chain: Chain,
        said: Digest256,
    },
    /// Body fetch errored at a layer below `NotFound` — network failure,
    /// remote 5xx, etc.
    #[error("{chain} SAD body fetch failed for peer {peer}: {source}")]
    BodyFetch {
        peer: Digest256,
        chain: Chain,
        #[source]
        source: KelsError,
    },
    /// Body parse failed — bytes were returned but didn't deserialize as
    /// the expected SAD type. Indicates a malformed publish, schema drift,
    /// or content tamper that bypassed SAID verification (the SAID check
    /// fires before this in normal flows).
    #[error("{chain} SAD body parse failed for peer {peer}: {source}")]
    BodyParse {
        peer: Digest256,
        chain: Chain,
        #[source]
        source: serde_json::Error,
    },
}

/// Walk every member of `federation.authPolicy` against their `peer/services`
/// chain. Returns success / failure breakdowns; never errors at the top
/// level. Clients (non-federation-member consumers) call this directly;
/// federation members typically call [`walk_federation_peers`].
pub async fn walk_peer_services(
    federation: &FederationState,
    evaluator: &FederationEvaluator,
    cascade: &(dyn SadStore + 'static),
) -> PeerChainDiscovery<PeerServicesSad> {
    walk_chain::<PeerServicesSad>(
        federation,
        evaluator,
        cascade,
        Chain::Services,
        compute_peer_services_sel_prefix,
    )
    .await
}

/// Walk every member of `federation.authPolicy` against their `peer/gossip`
/// chain. Body fetches resolve through the cascade; the remote layer enforces
/// `readPolicy` at the sadstore so only federation members succeed.
pub async fn walk_peer_gossip(
    federation: &FederationState,
    evaluator: &FederationEvaluator,
    cascade: &(dyn SadStore + 'static),
) -> PeerChainDiscovery<PeerGossipSad> {
    walk_chain::<PeerGossipSad>(
        federation,
        evaluator,
        cascade,
        Chain::Gossip,
        compute_peer_gossip_sel_prefix,
    )
    .await
}

/// Combined per-peer state for federation members: both `peer/services` and
/// `peer/gossip` walked from the same federation snapshot + cascade.
///
/// `unresolved` aggregates failures from both chains (each carries its own
/// `chain` field so operators can see which one failed).
#[derive(Debug, Default)]
pub struct FederationPeerDiscovery {
    pub services: BTreeMap<Digest256, PeerServicesSad>,
    pub gossip: BTreeMap<Digest256, PeerGossipSad>,
    pub unresolved: Vec<UnresolvedPeer>,
}

/// Walk both per-peer chains for every federation member. Composes
/// [`walk_peer_services`] and [`walk_peer_gossip`]; merges their unresolved
/// lists. Federation members call this; end-user clients use only
/// `walk_peer_services`.
pub async fn walk_federation_peers(
    federation: &FederationState,
    evaluator: &FederationEvaluator,
    cascade: &(dyn SadStore + 'static),
) -> FederationPeerDiscovery {
    let services = walk_peer_services(federation, evaluator, cascade).await;
    let gossip = walk_peer_gossip(federation, evaluator, cascade).await;
    let mut unresolved = services.unresolved;
    unresolved.extend(gossip.unresolved);
    FederationPeerDiscovery {
        services: services.resolved,
        gossip: gossip.resolved,
        unresolved,
    }
}

/// Shared inner walker: iterate members, run [`resolve_one_peer`], partition
/// outcomes. Generic over chain SAD type + per-chain prefix derivation.
async fn walk_chain<S>(
    federation: &FederationState,
    evaluator: &FederationEvaluator,
    cascade: &(dyn SadStore + 'static),
    chain: Chain,
    prefix_fn: fn(Digest256) -> Result<Digest256, KelsError>,
) -> PeerChainDiscovery<S>
where
    S: serde::de::DeserializeOwned,
{
    let mut discovery = PeerChainDiscovery::<S>::default();

    for peer in &federation.members {
        match resolve_one_peer::<S>(*peer, chain, prefix_fn, evaluator, cascade).await {
            Ok(sad) => {
                discovery.resolved.insert(*peer, sad);
            }
            Err(reason) => {
                // Cold-start / gossip-lag cases (`NoTip`, `BodyMissing`)
                // are expected on a fresh node and surface at debug-level;
                // chain-integrity failures escalate to warn so an operator
                // notices.
                match &reason {
                    DiscoveryError::NoTip { .. } | DiscoveryError::BodyMissing { .. } => {
                        debug!(peer = %peer, chain = %chain, error = %reason, "peer publication unresolved (transient)");
                    }
                    _ => {
                        warn!(peer = %peer, chain = %chain, error = %reason, "peer publication unresolved");
                    }
                }
                discovery.unresolved.push(UnresolvedPeer {
                    identity: *peer,
                    chain,
                    reason,
                });
            }
        }
    }

    discovery
}

async fn resolve_one_peer<S>(
    peer: Digest256,
    chain: Chain,
    prefix_fn: fn(Digest256) -> Result<Digest256, KelsError>,
    evaluator: &FederationEvaluator,
    cascade: &(dyn SadStore + 'static),
) -> Result<S, DiscoveryError>
where
    S: serde::de::DeserializeOwned,
{
    let sel_prefix = prefix_fn(peer).map_err(|source| DiscoveryError::PrefixDerive {
        peer,
        chain,
        source,
    })?;

    let mut loader = SadStorePageLoader::new(cascade);
    let verification = sel_completed_verification(
        &mut loader,
        &sel_prefix,
        Arc::clone(&evaluator.iel_aware_checker),
        Arc::clone(&evaluator.iel_resolver),
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await;
    let verification = match verification {
        Ok(v) => v,
        Err(KelsError::NotFound(_)) => return Err(DiscoveryError::NoTip { peer, chain }),
        Err(source) => {
            return Err(DiscoveryError::ChainVerification {
                peer,
                chain,
                source,
            });
        }
    };

    let tip: &SadEvent = verification.current_event();
    if tip.kind != SadEventKind::Sea {
        return Err(DiscoveryError::UpdTailedChain {
            peer,
            chain,
            tip_kind: tip.kind,
        });
    }
    let content_said = tip
        .content
        .as_ref()
        .copied()
        .ok_or(DiscoveryError::TipNoContent { peer, chain })?;

    let body = match cascade.load(&content_said).await {
        Ok(Some(body)) => body,
        Ok(None) => {
            return Err(DiscoveryError::BodyMissing {
                peer,
                chain,
                said: content_said,
            });
        }
        Err(source) => {
            return Err(DiscoveryError::BodyFetch {
                peer,
                chain,
                source,
            });
        }
    };

    serde_json::from_value::<S>(body).map_err(|source| DiscoveryError::BodyParse {
        peer,
        chain,
        source,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use async_trait::async_trait;
    use std::collections::BTreeMap;

    use kels_core::{
        AnchorEvaluation, IdentityEvent, IdentityEventKind, IelChainPosition,
        IelChainPositionBatch, IelResolver, IelSatisfaction, InMemorySadStore, PEER_GOSSIP_SEL_TOPIC,
        PEER_SERVICES_SEL_TOPIC, PagedIelSource, PolicyChecker, SadEvent, SadStore,
        UnavailableIelResolver,
    };
    use kels_policy::{Policy, PolicyResolver};

    use super::*;

    fn d(label: &[u8]) -> Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    // ==================== Test fixtures ====================

    struct AlwaysPassChecker;

    #[async_trait]
    impl PolicyChecker for AlwaysPassChecker {
        async fn evaluate(
            &self,
            _said: &Digest256,
            _policy_said: &Digest256,
        ) -> Result<AnchorEvaluation, KelsError> {
            Ok(AnchorEvaluation {
                satisfied: true,
                missing_anchors: Vec::new(),
            })
        }
        async fn is_immune(&self, _policy_said: &Digest256) -> Result<bool, KelsError> {
            Ok(true)
        }
    }

    struct StubIelResolver {
        identity: Digest256,
        events: BTreeMap<Digest256, (u64, IdentityEventKind, Digest256, Digest256)>,
    }

    #[async_trait]
    impl IelResolver for StubIelResolver {
        async fn fetch_iel_event(
            &self,
            _: &Digest256,
            said: &Digest256,
        ) -> Result<IdentityEvent, KelsError> {
            let (version, kind, auth, gov) = self
                .events
                .get(said)
                .copied()
                .ok_or_else(|| KelsError::NotFound(format!("stub iel event {}", said)))?;
            let topic = "kels/iel/v1/test";
            let mut event = IdentityEvent::icp(auth, gov, topic)?;
            event.version = version;
            event.kind = kind;
            event.said = *said;
            event.prefix = self.identity;
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
                .ok_or_else(|| KelsError::NotFound(format!("auth policy at {}", said)))
        }
        async fn resolve_governance_policy_at(
            &self,
            _: &Digest256,
            said: &Digest256,
        ) -> Result<Digest256, KelsError> {
            self.events
                .get(said)
                .map(|(_, _, _, gov)| *gov)
                .ok_or_else(|| KelsError::NotFound(format!("gov policy at {}", said)))
        }
        async fn iel_chain_positions(
            &self,
            _identity: &Digest256,
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
            said: &Digest256,
        ) -> Result<Digest256, KelsError> {
            if self.events.contains_key(said) {
                Ok(self.identity)
            } else {
                Err(KelsError::NotFound(format!("event {}", said)))
            }
        }
        async fn resolve_current_auth_policy(
            &self,
            identity: &Digest256,
        ) -> Result<Digest256, KelsError> {
            if identity != &self.identity {
                return Err(KelsError::NotFound(format!("identity {}", identity)));
            }
            self.events
                .values()
                .max_by_key(|(version, _, _, _)| *version)
                .map(|(_, _, auth, _)| *auth)
                .ok_or_else(|| KelsError::NotFound("no events".to_string()))
        }
    }

    fn evaluator_for(iel_resolver: Arc<dyn IelResolver + Send + Sync>) -> FederationEvaluator {
        struct DummyIelSource;
        #[async_trait]
        impl PagedIelSource for DummyIelSource {
            async fn fetch_page(
                &self,
                _: &Digest256,
                _: Option<&Digest256>,
                _: usize,
            ) -> Result<(Vec<IdentityEvent>, bool), KelsError> {
                Err(KelsError::NotFound("dummy iel source".to_string()))
            }
        }
        struct DummyPolicyResolver;
        #[async_trait]
        impl PolicyResolver for DummyPolicyResolver {
            async fn resolve_policy(
                &self,
                said: &Digest256,
            ) -> Result<Policy, kels_policy::PolicyError> {
                Err(kels_policy::PolicyError::ResolutionError(format!(
                    "dummy {}",
                    said
                )))
            }
        }
        FederationEvaluator {
            policy_resolver: Arc::new(DummyPolicyResolver),
            iel_resolver,
            iel_aware_checker: Arc::new(AlwaysPassChecker),
            iel_source: Arc::new(DummyIelSource),
        }
    }

    fn federation_with(members: &[Digest256]) -> FederationState {
        FederationState {
            iel_prefix: d(b"federation-iel"),
            current_auth_policy_said: d(b"federation-auth-policy"),
            members: members.iter().copied().collect(),
            governance_threshold: 3,
        }
    }

    fn stub_resolver_for(
        identity: Digest256,
        iel_event_said: Digest256,
    ) -> Arc<dyn IelResolver + Send + Sync> {
        let mut events = BTreeMap::new();
        events.insert(
            iel_event_said,
            (
                0,
                IdentityEventKind::Icp,
                d(b"auth-policy"),
                d(b"gov-policy"),
            ),
        );
        Arc::new(StubIelResolver { identity, events })
    }

    /// Stage [Icp, Upd, Sea] for a peer on the given chain (topic), pointing
    /// at the supplied SAD body. Returns the IEL event SAID used as the
    /// `identity_event` binding on Upd/Sea.
    async fn stage_chain(
        cascade: &dyn SadStore,
        peer: Digest256,
        topic: &str,
        sad_said: Digest256,
        sad_body: &serde_json::Value,
    ) -> Digest256 {
        let iel_event_said = d(format!("iel-event-{}-{}", peer, topic).as_bytes());
        cascade.store(&sad_said, sad_body).await.unwrap();
        let icp = SadEvent::icp(peer, topic).unwrap();
        let upd = SadEvent::upd(&icp, iel_event_said, sad_said).unwrap();
        let sea = SadEvent::sea(&upd, iel_event_said).unwrap();
        cascade.store_sel_event(&icp).await.unwrap();
        cascade.store_sel_event(&upd).await.unwrap();
        cascade.store_sel_event(&sea).await.unwrap();
        iel_event_said
    }

    // ==================== Services walker ====================

    #[tokio::test]
    async fn walks_peer_services_for_one_member() {
        let peer = d(b"peer-services-a");
        let cascade = InMemorySadStore::new();
        let sad = PeerServicesSad::create("alice.example.net".to_string()).unwrap();
        let body = serde_json::to_value(&sad).unwrap();
        let iel_event =
            stage_chain(&cascade, peer, PEER_SERVICES_SEL_TOPIC, sad.said, &body).await;

        let evaluator = evaluator_for(stub_resolver_for(peer, iel_event));
        let federation = federation_with(&[peer]);

        let discovery = walk_peer_services(&federation, &evaluator, &cascade).await;
        assert_eq!(discovery.resolved.len(), 1);
        assert_eq!(discovery.unresolved.len(), 0);
        assert_eq!(
            discovery.resolved.get(&peer).unwrap().domain,
            "alice.example.net"
        );
    }

    #[tokio::test]
    async fn services_walker_missing_chain_yields_no_tip() {
        let peer = d(b"peer-services-empty");
        let cascade = InMemorySadStore::new();
        let evaluator = evaluator_for(Arc::new(UnavailableIelResolver));
        let federation = federation_with(&[peer]);

        let discovery = walk_peer_services(&federation, &evaluator, &cascade).await;
        assert_eq!(discovery.resolved.len(), 0);
        assert!(matches!(
            discovery.unresolved[0].reason,
            DiscoveryError::NoTip { chain: Chain::Services, .. }
        ));
    }

    // ==================== Gossip walker ====================

    #[tokio::test]
    async fn walks_peer_gossip_for_one_member() {
        let peer = d(b"peer-gossip-a");
        let cascade = InMemorySadStore::new();
        let sad =
            PeerGossipSad::create(d(b"read-policy"), "203.0.113.4:4001".to_string()).unwrap();
        let body = serde_json::to_value(&sad).unwrap();
        let iel_event = stage_chain(&cascade, peer, PEER_GOSSIP_SEL_TOPIC, sad.said, &body).await;

        let evaluator = evaluator_for(stub_resolver_for(peer, iel_event));
        let federation = federation_with(&[peer]);

        let discovery = walk_peer_gossip(&federation, &evaluator, &cascade).await;
        assert_eq!(discovery.resolved.len(), 1);
        assert_eq!(
            discovery.resolved.get(&peer).unwrap().address,
            "203.0.113.4:4001"
        );
    }

    // ==================== Upd-tailed rejection ====================

    #[tokio::test]
    async fn upd_tailed_chain_is_rejected_with_chain_label() {
        let peer = d(b"peer-upd-tail");
        let cascade = InMemorySadStore::new();
        let sad =
            PeerGossipSad::create(d(b"read-policy"), "10.0.0.99:4001".to_string()).unwrap();
        let body = serde_json::to_value(&sad).unwrap();
        cascade.store(&sad.said, &body).await.unwrap();
        // Stage [Icp, Upd] only — no trailing Sea.
        let iel_event_said = d(b"iel-event-upd-tail");
        let icp = SadEvent::icp(peer, PEER_GOSSIP_SEL_TOPIC).unwrap();
        let upd = SadEvent::upd(&icp, iel_event_said, sad.said).unwrap();
        cascade.store_sel_event(&icp).await.unwrap();
        cascade.store_sel_event(&upd).await.unwrap();

        let evaluator = evaluator_for(stub_resolver_for(peer, iel_event_said));
        let federation = federation_with(&[peer]);

        let discovery = walk_peer_gossip(&federation, &evaluator, &cascade).await;
        assert_eq!(discovery.resolved.len(), 0);
        match &discovery.unresolved[0].reason {
            DiscoveryError::UpdTailedChain { chain, .. } => assert_eq!(*chain, Chain::Gossip),
            other => panic!("expected UpdTailedChain, got {other:?}"),
        }
    }

    // ==================== Body-missing surfaces ====================

    #[tokio::test]
    async fn missing_body_surfaces_body_missing() {
        let peer = d(b"peer-body-gone");
        let cascade = InMemorySadStore::new();
        // Stage [Icp, Upd, Sea] without storing the body — the tip's
        // content SAID has nothing behind it.
        let iel_event_said = d(b"iel-event-body-gone");
        let phantom_body_said = d(b"phantom-body-said");
        let icp = SadEvent::icp(peer, PEER_SERVICES_SEL_TOPIC).unwrap();
        let upd = SadEvent::upd(&icp, iel_event_said, phantom_body_said).unwrap();
        let sea = SadEvent::sea(&upd, iel_event_said).unwrap();
        cascade.store_sel_event(&icp).await.unwrap();
        cascade.store_sel_event(&upd).await.unwrap();
        cascade.store_sel_event(&sea).await.unwrap();

        let evaluator = evaluator_for(stub_resolver_for(peer, iel_event_said));
        let federation = federation_with(&[peer]);

        let discovery = walk_peer_services(&federation, &evaluator, &cascade).await;
        match &discovery.unresolved[0].reason {
            DiscoveryError::BodyMissing { said, chain, .. } => {
                assert_eq!(*said, phantom_body_said);
                assert_eq!(*chain, Chain::Services);
            }
            other => panic!("expected BodyMissing, got {other:?}"),
        }
    }

    // ==================== Composite walker ====================

    #[tokio::test]
    async fn walk_federation_peers_returns_both_chains_when_present() {
        let peer = d(b"peer-both");
        let cascade = InMemorySadStore::new();

        // Stage both chains for the same peer. The two chains use distinct
        // IEL bindings; we set up both in the stub resolver.
        let services_sad =
            PeerServicesSad::create("alice.example.net".to_string()).unwrap();
        let gossip_sad =
            PeerGossipSad::create(d(b"read-policy"), "10.0.0.10:4001".to_string()).unwrap();

        let services_body = serde_json::to_value(&services_sad).unwrap();
        let gossip_body = serde_json::to_value(&gossip_sad).unwrap();
        let services_iel = stage_chain(
            &cascade,
            peer,
            PEER_SERVICES_SEL_TOPIC,
            services_sad.said,
            &services_body,
        )
        .await;
        let gossip_iel = stage_chain(
            &cascade,
            peer,
            PEER_GOSSIP_SEL_TOPIC,
            gossip_sad.said,
            &gossip_body,
        )
        .await;

        // Resolver knows both IEL events.
        let mut events = BTreeMap::new();
        for said in [services_iel, gossip_iel] {
            events.insert(
                said,
                (
                    0,
                    IdentityEventKind::Icp,
                    d(b"auth-policy"),
                    d(b"gov-policy"),
                ),
            );
        }
        let resolver: Arc<dyn IelResolver + Send + Sync> =
            Arc::new(StubIelResolver { identity: peer, events });
        let evaluator = evaluator_for(resolver);
        let federation = federation_with(&[peer]);

        let discovery = walk_federation_peers(&federation, &evaluator, &cascade).await;
        assert_eq!(discovery.services.len(), 1);
        assert_eq!(discovery.gossip.len(), 1);
        assert_eq!(discovery.unresolved.len(), 0);
        assert_eq!(
            discovery.services.get(&peer).unwrap().domain,
            "alice.example.net"
        );
        assert_eq!(
            discovery.gossip.get(&peer).unwrap().address,
            "10.0.0.10:4001"
        );
    }

    #[tokio::test]
    async fn walk_federation_peers_partial_chain_yields_partial_resolution() {
        let peer = d(b"peer-services-only");
        let cascade = InMemorySadStore::new();
        // Stage only the services chain — gossip chain absent.
        let services_sad = PeerServicesSad::create("solo.example.net".to_string()).unwrap();
        let services_body = serde_json::to_value(&services_sad).unwrap();
        let services_iel = stage_chain(
            &cascade,
            peer,
            PEER_SERVICES_SEL_TOPIC,
            services_sad.said,
            &services_body,
        )
        .await;

        let evaluator = evaluator_for(stub_resolver_for(peer, services_iel));
        let federation = federation_with(&[peer]);

        let discovery = walk_federation_peers(&federation, &evaluator, &cascade).await;
        // Services resolved; gossip unresolved as NoTip.
        assert_eq!(discovery.services.len(), 1);
        assert_eq!(discovery.gossip.len(), 0);
        assert_eq!(discovery.unresolved.len(), 1);
        match &discovery.unresolved[0].reason {
            DiscoveryError::NoTip { chain: Chain::Gossip, .. } => {}
            other => panic!("expected NoTip on gossip chain, got {other:?}"),
        }
    }
}
