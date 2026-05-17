// Walker + per-peer outcome types are consumed by the next gap of #195
// (sync.rs / bootstrap.rs retire SharedAllowlist and route URL lookups
// through this walker). Suppress dead-code warnings module-wide until that
// hookup lands.
#![allow(dead_code)]

//! Per-peer address discovery: federation `authPolicy` → address SEL walk
//! → AddressSad body fetch → network endpoints.
//!
//! Layers above:
//! - [`crate::authorization::walk_federation_iel`] yields the
//!   [`FederationState`] whose `members` field enumerates currently-authorized
//!   peer identity prefixes.
//! - This module resolves each member's address SEL chain via the supplied
//!   cascade, verifies the chain end-to-end with [`sel_completed_verification`],
//!   and returns the published [`AddressSad`] body.
//!
//! Per `docs/design/infrastructure/discovery.md`, the chain's tip must be a
//! `Sea` event under the federation address-SEL convention — an `Upd`-tailed
//! chain is structurally invalid and is rejected.
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
    AddressSad, KelsError, SadEvent, SadEventKind, SadStore, SadStorePageLoader,
    compute_address_sel_prefix, sel_completed_verification,
};

use crate::authorization::{FederationEvaluator, FederationState};

/// Result of walking every member of the federation's `authPolicy`.
#[derive(Debug, Default)]
pub struct PeerAddressDiscovery {
    /// Members whose address SEL was verified and whose published
    /// [`AddressSad`] body was fetched. Iterate this map for dial
    /// candidates.
    pub resolved: BTreeMap<Digest256, AddressSad>,
    /// Members whose chain or body was unreachable / malformed when this
    /// walk ran. Logged for operator visibility; not a fatal condition —
    /// anti-entropy fills the gaps on the next pass.
    pub unresolved: Vec<UnresolvedPeer>,
}

#[derive(Debug)]
pub struct UnresolvedPeer {
    pub identity: Digest256,
    pub reason: DiscoveryError,
}

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("failed to derive address SEL prefix for peer {peer}: {source}")]
    PrefixDerive {
        peer: Digest256,
        #[source]
        source: KelsError,
    },
    #[error("address SEL chain verification failed for peer {peer}: {source}")]
    ChainVerification {
        peer: Digest256,
        #[source]
        source: KelsError,
    },
    /// Chain tip is an `Upd` rather than a trailing `Sea`. Per the federation
    /// address-SEL convention (see `peer-identity.md §HSM ceremony step 4`
    /// and `protocol-doctrine.md §Sea-after-Upd ratchet`), conforming
    /// tooling never emits an Upd-tailed chain; reject the chain rather
    /// than treating a pre-seal Upd as the current endpoint set.
    #[error(
        "address SEL for peer {peer} has unsealed tip {tip_kind}; conforming tooling never \
         produces an Upd-tailed address SEL"
    )]
    UpdTailedChain { peer: Digest256, tip_kind: SadEventKind },
    /// Verifier returned no current event — peer's chain is empty or
    /// unreachable in the cascade (typical during cold start / gossip lag).
    #[error("address SEL for peer {peer} has no current event yet")]
    NoTip { peer: Digest256 },
    /// Tip event is `Sea` but its preserved `content` field is `None`.
    /// Structurally impossible under the convention (Sea preserves the
    /// Upd's content), but surfaced explicitly so a server bug or
    /// malformed event doesn't silently pass through.
    #[error("address SEL tip for peer {peer} has no content SAID")]
    TipNoContent { peer: Digest256 },
    /// AddressSad body for the tip's content SAID isn't fetchable. Either
    /// the body hasn't propagated yet (cold start) or the cache + remote
    /// both miss.
    #[error("address SAD body {said} not found for peer {peer}")]
    BodyMissing { peer: Digest256, said: Digest256 },
    /// Body fetch errored at a layer below `NotFound` — network failure,
    /// remote 5xx, etc.
    #[error("address SAD body fetch failed for peer {peer}: {source}")]
    BodyFetch {
        peer: Digest256,
        #[source]
        source: KelsError,
    },
    /// Body parse failed — bytes were returned but didn't deserialize as
    /// an [`AddressSad`]. Indicates a malformed publish, schema drift, or
    /// content tamper that bypassed SAID verification (the SAID check
    /// fires before this in normal flows).
    #[error("address SAD body parse failed for peer {peer}: {source}")]
    BodyParse {
        peer: Digest256,
        #[source]
        source: serde_json::Error,
    },
}

/// Walk each member of `federation.authPolicy` to their current address SAD.
///
/// Reads the address SEL chain via the supplied `cascade` (typically
/// `CascadingSadStore[RepositorySadStore, RemoteSadStore]`); verifies the
/// chain with [`sel_completed_verification`] using the evaluator's policy
/// checker and IEL resolver; fetches the AddressSad body at the tip's
/// `content` SAID via `cascade.load`.
///
/// Returns success and failure breakdowns; never errors at the top level.
/// Caller iterates `resolved` for dial candidates and inspects `unresolved`
/// for operator-visible failures.
pub async fn walk_peer_addresses(
    federation: &FederationState,
    evaluator: &FederationEvaluator,
    cascade: &(dyn SadStore + 'static),
) -> PeerAddressDiscovery {
    let mut discovery = PeerAddressDiscovery::default();

    for peer in &federation.members {
        match resolve_one_peer(*peer, evaluator, cascade).await {
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
                        debug!(peer = %peer, error = %reason, "peer address unresolved (transient)");
                    }
                    _ => {
                        warn!(peer = %peer, error = %reason, "peer address unresolved");
                    }
                }
                discovery.unresolved.push(UnresolvedPeer {
                    identity: *peer,
                    reason,
                });
            }
        }
    }

    discovery
}

async fn resolve_one_peer(
    peer: Digest256,
    evaluator: &FederationEvaluator,
    cascade: &(dyn SadStore + 'static),
) -> Result<AddressSad, DiscoveryError> {
    let sel_prefix = compute_address_sel_prefix(peer)
        .map_err(|source| DiscoveryError::PrefixDerive { peer, source })?;

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
        Err(KelsError::NotFound(_)) => return Err(DiscoveryError::NoTip { peer }),
        Err(source) => return Err(DiscoveryError::ChainVerification { peer, source }),
    };

    let tip: &SadEvent = verification.current_event();
    if tip.kind != SadEventKind::Sea {
        return Err(DiscoveryError::UpdTailedChain {
            peer,
            tip_kind: tip.kind,
        });
    }
    let content_said = tip
        .content
        .as_ref()
        .copied()
        .ok_or(DiscoveryError::TipNoContent { peer })?;

    let body = match cascade.load(&content_said).await {
        Ok(Some(body)) => body,
        Ok(None) => {
            return Err(DiscoveryError::BodyMissing {
                peer,
                said: content_said,
            });
        }
        Err(source) => return Err(DiscoveryError::BodyFetch { peer, source }),
    };

    serde_json::from_value::<AddressSad>(body)
        .map_err(|source| DiscoveryError::BodyParse { peer, source })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use async_trait::async_trait;
    use std::collections::BTreeMap;

    use kels_core::{
        AnchorEvaluation, Endpoint, IdentityEvent, IdentityEventKind, IelChainPosition,
        IelChainPositionBatch, IelResolver, IelSatisfaction, InMemorySadStore, PagedIelSource,
        PolicyChecker, SadEvent, SadStore, UnavailableIelResolver,
    };
    use kels_policy::{Policy, PolicyResolver};

    use super::*;

    fn d(label: &[u8]) -> Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    // ==================== Test fixtures ====================

    /// Permissive checker: every anchor evaluation passes, every policy is
    /// "immune". Sufficient for the walker — its job is structural chain
    /// verification, not anchor validation.
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

    /// Hand-built IEL resolver: knows one identity's binding event(s) and
    /// their declared `auth_policy` / `governance_policy`.
    struct StubIelResolver {
        identity: Digest256,
        // (said, version, kind, auth_policy, governance_policy)
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
            // Build a minimal IdentityEvent with the SAID overridden after
            // construction. Tests don't care about chain integrity here —
            // the SelVerifier consults `resolve_auth_policy_at` and
            // `resolve_governance_policy_at`, not `fetch_iel_event`'s
            // full body — but a well-formed event is preferable.
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

    /// `FederationEvaluator` wired with the always-pass checker and a stub
    /// resolver. The `iel_source` and `policy_resolver` aren't consulted by
    /// the walker's path, so we point them at sentinel impls.
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

    /// Federation state with the given members.
    fn federation_with(members: &[Digest256]) -> FederationState {
        FederationState {
            iel_prefix: d(b"federation-iel"),
            current_auth_policy_said: d(b"federation-auth-policy"),
            members: members.iter().copied().collect(),
            governance_threshold: 3,
        }
    }

    /// Stage [Icp, Upd, Sea] in the cascade and publish the AddressSad body.
    /// Returns the IEL event SAID and the AddressSad.
    async fn stage_peer_chain(
        cascade: &dyn SadStore,
        peer: Digest256,
        endpoint_addr: &str,
    ) -> (Digest256, AddressSad) {
        let iel_event_said = d(format!("iel-event-{}", peer).as_bytes());
        let address_sad = AddressSad::create(
            d(b"read-policy"),
            vec![Endpoint {
                address: endpoint_addr.to_string(),
                region: None,
            }],
        )
        .unwrap();

        let body = serde_json::to_value(&address_sad).unwrap();
        cascade.store(&address_sad.said, &body).await.unwrap();

        let icp = SadEvent::icp(peer, kels_core::ADDRESS_SEL_TOPIC).unwrap();
        let upd = SadEvent::upd(&icp, iel_event_said, address_sad.said).unwrap();
        let sea = SadEvent::sea(&upd, iel_event_said).unwrap();
        cascade.store_sel_event(&icp).await.unwrap();
        cascade.store_sel_event(&upd).await.unwrap();
        cascade.store_sel_event(&sea).await.unwrap();

        (iel_event_said, address_sad)
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

    // ==================== Walker happy path ====================

    #[tokio::test]
    async fn resolves_one_peer_with_complete_chain() {
        let peer = d(b"peer-a");
        let cascade = InMemorySadStore::new();
        let (iel_event, address_sad) = stage_peer_chain(&cascade, peer, "10.0.0.1:4001").await;

        let evaluator = evaluator_for(stub_resolver_for(peer, iel_event));
        let federation = federation_with(&[peer]);

        let discovery = walk_peer_addresses(&federation, &evaluator, &cascade).await;

        assert_eq!(discovery.unresolved.len(), 0);
        assert_eq!(discovery.resolved.len(), 1);
        let resolved = discovery.resolved.get(&peer).unwrap();
        assert_eq!(resolved.said, address_sad.said);
        assert_eq!(resolved.endpoints.len(), 1);
        assert_eq!(resolved.endpoints[0].address, "10.0.0.1:4001");
    }

    // ==================== Walker failure paths ====================

    #[tokio::test]
    async fn missing_chain_surfaces_no_tip() {
        let peer = d(b"peer-no-chain");
        let cascade = InMemorySadStore::new();
        // No staging — the peer's prefix has no events.

        let evaluator = evaluator_for(Arc::new(UnavailableIelResolver));
        let federation = federation_with(&[peer]);

        let discovery = walk_peer_addresses(&federation, &evaluator, &cascade).await;

        assert_eq!(discovery.resolved.len(), 0);
        assert_eq!(discovery.unresolved.len(), 1);
        let outcome = &discovery.unresolved[0];
        assert_eq!(outcome.identity, peer);
        assert!(
            matches!(outcome.reason, DiscoveryError::NoTip { .. }),
            "expected NoTip, got {:?}",
            outcome.reason
        );
    }

    #[tokio::test]
    async fn upd_tailed_chain_is_rejected() {
        let peer = d(b"peer-upd-tail");
        let cascade = InMemorySadStore::new();

        // Stage [Icp, Upd] only — no Sea. Conforming tooling never produces
        // this, but a malformed publish could.
        let iel_event_said = d(b"iel-event-upd-tail");
        let address_sad = AddressSad::create(
            d(b"read-policy"),
            vec![Endpoint {
                address: "10.0.0.99:4001".to_string(),
                region: None,
            }],
        )
        .unwrap();
        cascade
            .store(&address_sad.said, &serde_json::to_value(&address_sad).unwrap())
            .await
            .unwrap();
        let icp = SadEvent::icp(peer, kels_core::ADDRESS_SEL_TOPIC).unwrap();
        let upd = SadEvent::upd(&icp, iel_event_said, address_sad.said).unwrap();
        cascade.store_sel_event(&icp).await.unwrap();
        cascade.store_sel_event(&upd).await.unwrap();

        let evaluator = evaluator_for(stub_resolver_for(peer, iel_event_said));
        let federation = federation_with(&[peer]);

        let discovery = walk_peer_addresses(&federation, &evaluator, &cascade).await;

        assert_eq!(discovery.resolved.len(), 0);
        assert_eq!(discovery.unresolved.len(), 1);
        let outcome = &discovery.unresolved[0];
        assert!(
            matches!(outcome.reason, DiscoveryError::UpdTailedChain { .. }),
            "expected UpdTailedChain, got {:?}",
            outcome.reason
        );
    }

    #[tokio::test]
    async fn missing_body_surfaces_body_missing() {
        let peer = d(b"peer-body-gone");
        let cascade = InMemorySadStore::new();

        // Stage [Icp, Upd, Sea] without storing the body — the tip's
        // content SAID has nothing behind it.
        let iel_event_said = d(b"iel-event-body-gone");
        let phantom_body_said = d(b"phantom-body-said");
        let icp = SadEvent::icp(peer, kels_core::ADDRESS_SEL_TOPIC).unwrap();
        let upd = SadEvent::upd(&icp, iel_event_said, phantom_body_said).unwrap();
        let sea = SadEvent::sea(&upd, iel_event_said).unwrap();
        cascade.store_sel_event(&icp).await.unwrap();
        cascade.store_sel_event(&upd).await.unwrap();
        cascade.store_sel_event(&sea).await.unwrap();

        let evaluator = evaluator_for(stub_resolver_for(peer, iel_event_said));
        let federation = federation_with(&[peer]);

        let discovery = walk_peer_addresses(&federation, &evaluator, &cascade).await;

        assert_eq!(discovery.resolved.len(), 0);
        let outcome = &discovery.unresolved[0];
        match &outcome.reason {
            DiscoveryError::BodyMissing { said, .. } => assert_eq!(*said, phantom_body_said),
            other => panic!("expected BodyMissing, got {other:?}"),
        }
    }

    // ==================== Multi-peer partial success ====================

    #[tokio::test]
    async fn multi_peer_walk_partitions_success_and_failure() {
        let alice = d(b"peer-alice-multi");
        let bob = d(b"peer-bob-no-chain");
        let cascade = InMemorySadStore::new();

        let (alice_iel_event, alice_sad) = stage_peer_chain(&cascade, alice, "10.0.0.10:4001").await;
        // Bob has no events.

        // The IEL resolver only knows alice's binding; bob's chain doesn't
        // exist so no resolver calls fire for him anyway.
        let evaluator = evaluator_for(stub_resolver_for(alice, alice_iel_event));
        let federation = federation_with(&[alice, bob]);

        let discovery = walk_peer_addresses(&federation, &evaluator, &cascade).await;

        assert_eq!(discovery.resolved.len(), 1);
        assert_eq!(discovery.resolved.get(&alice).unwrap().said, alice_sad.said);

        assert_eq!(discovery.unresolved.len(), 1);
        assert_eq!(discovery.unresolved[0].identity, bob);
        assert!(matches!(
            discovery.unresolved[0].reason,
            DiscoveryError::NoTip { .. }
        ));
    }
}
