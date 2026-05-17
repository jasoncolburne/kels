//! Per-peer service URL resolution from `peer/services` SAD chains.
//!
//! The [`AddressResolver`] trait is the consumer-side interface for
//! translating peer identities (IEL prefixes) into reachable service URLs:
//!
//! - [`AddressResolver::resolve_domain`] — single-peer lookup; returns the
//!   peer's published base domain (from the `peer/services` SAD), or `None`
//!   if the peer is unknown / hasn't published yet / its publication is
//!   unreachable.
//! - [`AddressResolver::list_domains`] — all known peers' `(iel_prefix,
//!   base_domain)` pairs. Used for fan-out broadcast paths.
//!
//! Service URLs are derived from the domain via the subdomain convention
//! ([`service_url`] helper) — see
//! `docs/design/infrastructure/federation.md §peer/services SAD`.
//!
//! Two impls ship:
//!
//! - [`ClientAddressResolver`] (this module) — peer-set provided up-front by
//!   the caller; no federation membership context. Used by clients that walk
//!   `peer/services` for a known list of peers (mobile / desktop / CLI).
//! - `FederationAddressResolver` (in `services/gossip`) — federation-aware;
//!   enumerates members from a `FederationEvaluator`'s federation IEL walk.
//!
//! Implementations walk the chain fresh on every call. URL lookup is an
//! addressing concern, not a chain-state security decision, so caching is
//! permissible at the impl level — but the trait does not require it.

use std::sync::Arc;

use async_trait::async_trait;
use cesr::Digest256;

use crate::{
    IelResolver, PeerServicesSad, PolicyChecker, SadEvent, SadEventKind, SadStorePageLoader,
    compute_peer_services_sel_prefix, error::KelsError, sel_completed_verification,
};

/// Derive a service URL from a peer's published base domain via the
/// subdomain convention `http://{service}.{domain}`.
///
/// Examples (with `domain = "node-a.example.net"`):
/// - `service_url("kels", "node-a.example.net")` →
///   `"http://kels.node-a.example.net"`
/// - `service_url("sadstore", "node-a.example.net")` →
///   `"http://sadstore.node-a.example.net"`
pub fn service_url(service: &str, domain: &str) -> String {
    format!("http://{service}.{domain}")
}

#[async_trait]
pub trait AddressResolver: Send + Sync {
    /// Look up a single peer's published base domain.
    async fn resolve_domain(
        &self,
        peer_identity: &Digest256,
    ) -> Result<Option<String>, KelsError>;

    /// Enumerate `(peer_identity, base_domain)` for every peer the resolver
    /// has a publication for. Order is implementation-defined.
    async fn list_domains(&self) -> Result<Vec<(Digest256, String)>, KelsError>;
}

/// Resolves `peer/services` publications for a caller-supplied set of peer
/// identities, with no federation membership context.
///
/// Used by clients (mobile / desktop / CLI) that need to reach a known set
/// of peers but aren't themselves federation members. Federation-aware
/// callers should use the gossip-side `FederationAddressResolver` instead.
///
/// Excludes the caller's own identity if `local_identity` is set (matches
/// the gossip-side broadcaster semantics — never broadcast to self).
pub struct ClientAddressResolver {
    peers: Vec<Digest256>,
    local_identity: Option<Digest256>,
    cascade: Arc<dyn crate::store::SadStore>,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    iel_resolver: Arc<dyn IelResolver + Send + Sync>,
}

impl ClientAddressResolver {
    pub fn new(
        peers: Vec<Digest256>,
        local_identity: Option<Digest256>,
        cascade: Arc<dyn crate::store::SadStore>,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
        iel_resolver: Arc<dyn IelResolver + Send + Sync>,
    ) -> Self {
        Self {
            peers,
            local_identity,
            cascade,
            checker,
            iel_resolver,
        }
    }
}

#[async_trait]
impl AddressResolver for ClientAddressResolver {
    async fn resolve_domain(
        &self,
        peer_identity: &Digest256,
    ) -> Result<Option<String>, KelsError> {
        if Some(*peer_identity) == self.local_identity {
            return Ok(None);
        }
        if !self.peers.contains(peer_identity) {
            return Ok(None);
        }
        resolve_peer_services_domain(
            *peer_identity,
            self.cascade.as_ref(),
            Arc::clone(&self.checker),
            Arc::clone(&self.iel_resolver),
        )
        .await
    }

    async fn list_domains(&self) -> Result<Vec<(Digest256, String)>, KelsError> {
        let mut out = Vec::new();
        for peer in &self.peers {
            if Some(*peer) == self.local_identity {
                continue;
            }
            if let Some(domain) = resolve_peer_services_domain(
                *peer,
                self.cascade.as_ref(),
                Arc::clone(&self.checker),
                Arc::clone(&self.iel_resolver),
            )
            .await?
            {
                out.push((*peer, domain));
            }
        }
        Ok(out)
    }
}

/// Resolve a single peer's `peer/services` chain to its current base domain.
///
/// Shared between [`ClientAddressResolver`] and the gossip-side federation
/// resolver. Walks the chain through the cascade, requires a `Sea`-tipped
/// chain (no Upd-tailed publications), fetches the SAD body, parses as
/// [`PeerServicesSad`], returns the `domain`.
///
/// Returns `Ok(None)` on transient failures (chain absent, body absent —
/// typical during cold start / gossip lag) and propagates structural
/// failures as `Err`. Chain-integrity errors (verification failure,
/// Upd-tailed tip) propagate so callers can log them.
pub async fn resolve_peer_services_domain(
    peer_identity: Digest256,
    cascade: &dyn crate::store::SadStore,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
    iel_resolver: Arc<dyn IelResolver + Send + Sync>,
) -> Result<Option<String>, KelsError> {
    let prefix = compute_peer_services_sel_prefix(peer_identity)?;
    let mut loader = SadStorePageLoader::new(cascade);
    let verification = match sel_completed_verification(
        &mut loader,
        &prefix,
        Arc::clone(&checker),
        iel_resolver,
        crate::page_size(),
        crate::max_pages(),
    )
    .await
    {
        Ok(v) => v,
        // Cold-start or gossip-lag: the chain hasn't propagated yet. Surface
        // as "no domain known"; the caller will retry on the next refresh.
        Err(KelsError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e),
    };

    let tip: &SadEvent = verification.current_event();
    if tip.kind != SadEventKind::Sea {
        return Err(KelsError::VerificationFailed(format!(
            "peer/services for peer {peer_identity} has unsealed tip {tip_kind}; \
             conforming tooling never produces an Upd-tailed chain",
            tip_kind = tip.kind,
        )));
    }
    let Some(content_said) = tip.content.as_ref().copied() else {
        return Err(KelsError::VerificationFailed(format!(
            "peer/services tip for peer {peer_identity} has no content SAID"
        )));
    };

    let body = match cascade.load(&content_said).await? {
        Some(b) => b,
        None => return Ok(None),
    };
    let sad: PeerServicesSad = serde_json::from_value(body)?;
    Ok(Some(sad.domain))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use async_trait::async_trait;
    use std::collections::BTreeMap;

    use super::*;
    use crate::store::{InMemorySadStore, SadStore as SadStoreTrait};
    use crate::{
        AnchorEvaluation, IdentityEvent, IdentityEventKind, IelChainPosition,
        IelChainPositionBatch, IelSatisfaction, PEER_SERVICES_SEL_TOPIC, PeerServicesSad, SadEvent,
    };

    fn d(label: &[u8]) -> Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    // ==================== Fixtures ====================

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
            let mut event = IdentityEvent::icp(auth, gov, "kels/iel/v1/test")?;
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
                .max_by_key(|(v, _, _, _)| *v)
                .map(|(_, _, a, _)| *a)
                .ok_or_else(|| KelsError::NotFound("no events".into()))
        }
    }

    fn stub_resolver_for(identity: Digest256, iel_event: Digest256) -> Arc<dyn IelResolver + Send + Sync> {
        let mut events = BTreeMap::new();
        events.insert(
            iel_event,
            (
                0,
                IdentityEventKind::Icp,
                d(b"auth-policy"),
                d(b"gov-policy"),
            ),
        );
        Arc::new(StubIelResolver { identity, events })
    }

    async fn stage_services_chain(
        cascade: &dyn SadStoreTrait,
        peer: Digest256,
        domain: &str,
    ) -> (Digest256, PeerServicesSad) {
        let iel_event = d(format!("iel-event-{}", peer).as_bytes());
        let sad = PeerServicesSad::create(domain.to_string()).unwrap();
        cascade
            .store(&sad.said, &serde_json::to_value(&sad).unwrap())
            .await
            .unwrap();
        let icp = SadEvent::icp(peer, PEER_SERVICES_SEL_TOPIC).unwrap();
        let upd = SadEvent::upd(&icp, iel_event, sad.said).unwrap();
        let sea = SadEvent::sea(&upd, iel_event).unwrap();
        cascade.store_sel_event(&icp).await.unwrap();
        cascade.store_sel_event(&upd).await.unwrap();
        cascade.store_sel_event(&sea).await.unwrap();
        (iel_event, sad)
    }

    // ==================== service_url ====================

    #[test]
    fn service_url_formats_subdomain() {
        assert_eq!(
            service_url("kels", "node-a.example.net"),
            "http://kels.node-a.example.net"
        );
        assert_eq!(
            service_url("sadstore", "node-a.example.net"),
            "http://sadstore.node-a.example.net"
        );
        assert_eq!(
            service_url("mail", "node-a.example.net"),
            "http://mail.node-a.example.net"
        );
    }

    // ==================== ClientAddressResolver ====================

    #[tokio::test]
    async fn client_resolver_returns_published_domain() {
        let peer = d(b"peer-a");
        let cascade: Arc<dyn SadStoreTrait> = Arc::new(InMemorySadStore::new());
        let (iel_event, _sad) = stage_services_chain(cascade.as_ref(), peer, "node-a.example.net").await;

        let resolver = ClientAddressResolver::new(
            vec![peer],
            None,
            Arc::clone(&cascade),
            Arc::new(AlwaysPassChecker),
            stub_resolver_for(peer, iel_event),
        );

        assert_eq!(
            resolver.resolve_domain(&peer).await.unwrap(),
            Some("node-a.example.net".to_string())
        );
    }

    #[tokio::test]
    async fn client_resolver_returns_none_for_unknown_peer() {
        let known = d(b"peer-known");
        let unknown = d(b"peer-unknown");
        let cascade: Arc<dyn SadStoreTrait> = Arc::new(InMemorySadStore::new());
        let (iel_event, _) = stage_services_chain(cascade.as_ref(), known, "known.example.net").await;

        let resolver = ClientAddressResolver::new(
            vec![known],
            None,
            Arc::clone(&cascade),
            Arc::new(AlwaysPassChecker),
            stub_resolver_for(known, iel_event),
        );

        assert_eq!(resolver.resolve_domain(&unknown).await.unwrap(), None);
    }

    #[tokio::test]
    async fn client_resolver_skips_local_identity_in_list() {
        let self_peer = d(b"peer-self");
        let other = d(b"peer-other");
        let cascade: Arc<dyn SadStoreTrait> = Arc::new(InMemorySadStore::new());
        let (other_iel_event, _) =
            stage_services_chain(cascade.as_ref(), other, "other.example.net").await;
        let (self_iel_event, _) =
            stage_services_chain(cascade.as_ref(), self_peer, "self.example.net").await;

        // Stub resolver knows both — we expose only `other`'s chain via the
        // resolver's known peers, with self excluded.
        let mut events = BTreeMap::new();
        for (iel_event, identity) in [(other_iel_event, other), (self_iel_event, self_peer)] {
            events.insert(
                iel_event,
                (
                    0,
                    IdentityEventKind::Icp,
                    d(b"auth-policy"),
                    d(b"gov-policy"),
                ),
            );
            // StubIelResolver requires one identity per resolver; we use the
            // simple form with `other` as the bound identity and provide
            // the `self_peer` chain by accepting its events (the verifier
            // only consults resolve_auth_policy_at + resolve_governance_policy_at,
            // both of which look up by said, not by identity).
            let _ = identity;
        }
        let iel_resolver: Arc<dyn IelResolver + Send + Sync> = Arc::new(StubIelResolver {
            identity: other,
            events,
        });

        let resolver = ClientAddressResolver::new(
            vec![self_peer, other],
            Some(self_peer),
            Arc::clone(&cascade),
            Arc::new(AlwaysPassChecker),
            iel_resolver,
        );

        let list = resolver.list_domains().await.unwrap();
        let identities: Vec<Digest256> = list.iter().map(|(i, _)| *i).collect();
        assert!(!identities.contains(&self_peer), "self must be excluded");
        assert!(identities.contains(&other), "other present");

        // resolve_domain for self also returns None.
        assert_eq!(resolver.resolve_domain(&self_peer).await.unwrap(), None);
    }

    #[tokio::test]
    async fn client_resolver_returns_none_on_missing_chain() {
        let peer = d(b"peer-no-chain");
        let cascade: Arc<dyn SadStoreTrait> = Arc::new(InMemorySadStore::new());

        let resolver = ClientAddressResolver::new(
            vec![peer],
            None,
            Arc::clone(&cascade),
            Arc::new(AlwaysPassChecker),
            stub_resolver_for(peer, d(b"unused-iel-event")),
        );
        assert_eq!(resolver.resolve_domain(&peer).await.unwrap(), None);
    }
}
