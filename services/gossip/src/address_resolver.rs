// Consumed in the next gap of #195 — the SharedAllowlist retirement
// threads this resolver through sync.rs/bootstrap.rs/lib.rs. Suppress
// dead-code warnings module-wide until that hookup lands.
#![allow(dead_code)]

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
