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
    use crate::testing::{FederationFixture, blake3_label};

    // Fixture/helpers moved to `crate::testing`. Test bodies follow.

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
