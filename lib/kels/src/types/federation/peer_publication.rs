//! Per-peer publication SADs and their SEL chains.
//!
//! A federation member publishes two per-peer SEL chains:
//!
//! - **`peer/services`** — public service base domain. `PeerServicesSad`
//!   carries `{ said, domain }`; consumers derive service URLs via the
//!   subdomain convention `http://{service}.{domain}` (e.g. `kels.{domain}`,
//!   `sadstore.{domain}`). No `readPolicy`; the chain and the SAD are both
//!   publicly fetchable.
//! - **`peer/gossip`** — gossip mesh endpoint, federation-gated.
//!   `PeerGossipSad` carries `{ said, readPolicy, address }`; the `address`
//!   is a TCP gossip endpoint expressed as `host:port`. The `readPolicy`
//!   resolves to a policy SAD with expression `iel(FEDERATION_IEL_PREFIX)`
//!   so only currently-authorized federation members can fetch the body.
//!
//! Both chains follow `[Icp, Upd, Sea]` at inception and `[Upd, Sea]` at
//! rotation, per the Sea-after-Upd ratchet. The authoring helpers
//! ([`incept_peer_services_sel`] et al.) stage the batch and publish the SAD
//! body via the supplied cascade; KEL anchoring + flush stay caller-side.
//!
//! Discovery walks the chains separately (gossip-side walker). End-user
//! clients walk only `peer/services`; federation members walk both.
//!
//! Design: `docs/design/infrastructure/federation.md §Per-peer publication`,
//! `docs/design/infrastructure/discovery.md`,
//! `docs/design/infrastructure/peer-identity.md`.

use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

use crate::{
    SadEventBuilder, error::KelsError, store::sad::SadStore,
    types::sad::compute_sad_event_prefix,
};

// ==================== Topics ====================

/// SEL chain topic for the public per-peer services SAD. Embedded in the
/// chain's `topic` field at `Icp` and participates in chain-prefix
/// derivation alongside the peer's identity prefix — see
/// [`compute_peer_services_sel_prefix`]. Re-exported as
/// `PEER_SERVICES_SEL_TOPIC` from `services/gossip/src/gossip_layer.rs` for
/// the discovery walker.
pub const PEER_SERVICES_SEL_TOPIC: &str = "kels/sel/v1/peer/services";

/// SEL chain topic for the federation-gated per-peer gossip endpoint SAD.
pub const PEER_GOSSIP_SEL_TOPIC: &str = "kels/sel/v1/peer/gossip";

// ==================== SAD types ====================

/// Public per-peer services publication. Single `domain` field; consumers
/// derive service URLs via the subdomain convention
/// `http://{service}.{domain}` (e.g. `kels.example.net`,
/// `sadstore.example.net`, `mail.example.net`).
///
/// The subdomain convention is documented canonically in
/// `docs/design/infrastructure/federation.md §Per-peer publication`; the
/// SAD is structurally incomplete without it.
///
/// Public fetch path — no `readPolicy`. The chain itself (`Icp` / `Upd` /
/// `Sea`) is also public per `sadstore.md §Custody`.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct PeerServicesSad {
    #[said]
    pub said: cesr::Digest256,
    /// Peer's published base domain. Service URLs are derived as
    /// `http://{service}.{domain}` by consumers (no protocol or path
    /// indirection — the convention is fixed).
    pub domain: String,
}

/// Federation-gated per-peer gossip endpoint publication. Single
/// `host:port` address; rotation publishes a fresh SAD with the new
/// address.
///
/// `readPolicy` is the SAID of a policy SAD with expression
/// `iel(FEDERATION_IEL_PREFIX)`. Per `sadstore.md §Custody`, this gates
/// fetch-time access via `evaluate_signed_policy` against a
/// `SignedRequest`'s verified prefix set — only currently-authorized
/// federation members can fetch the body. The SEL chain itself still
/// gossips publicly; only the SAD body is gated.
///
/// No `role` / capability field by design — capabilities derive from the
/// federation IEL's `authPolicy`, not from peer self-declaration.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct PeerGossipSad {
    #[said]
    pub said: cesr::Digest256,
    /// SAID of the policy SAD gating fetch access.
    pub read_policy: cesr::Digest256,
    /// TCP gossip endpoint expressed as `host:port` (IPv4, bracketed IPv6,
    /// or hostname). Gossip carries its own transport
    /// (ML-KEM-1024 + ML-DSA-65/87 + AES-GCM-256); only the network
    /// endpoint travels here.
    pub address: String,
}

// ==================== Prefix derivation ====================

/// Compute the deterministic peer-services SEL prefix for a peer identity.
///
/// Wraps [`compute_sad_event_prefix`] with the fixed
/// [`PEER_SERVICES_SEL_TOPIC`]. Given the peer's identity prefix (listed
/// in the federation IEL's `authPolicy`), any node can compute this
/// offline — no directory service.
pub fn compute_peer_services_sel_prefix(
    peer_identity: cesr::Digest256,
) -> Result<cesr::Digest256, KelsError> {
    compute_sad_event_prefix(peer_identity, PEER_SERVICES_SEL_TOPIC)
}

/// Compute the deterministic peer-gossip SEL prefix for a peer identity.
/// Same offline-derivable property as [`compute_peer_services_sel_prefix`].
pub fn compute_peer_gossip_sel_prefix(
    peer_identity: cesr::Digest256,
) -> Result<cesr::Digest256, KelsError> {
    compute_sad_event_prefix(peer_identity, PEER_GOSSIP_SEL_TOPIC)
}

// ==================== Authoring helpers ====================

/// SAIDs of the three events staged by an inception helper.
///
/// Returned so the caller can anchor each SAID in the peer-identity KEL
/// before calling [`SadEventBuilder::flush`] — the SEL submit handler's
/// anchor checks fire against the IEL-resolved `authPolicy` /
/// `governancePolicy`.
#[derive(Debug, Clone)]
pub struct PeerSelInceptionBatch {
    pub icp: cesr::Digest256,
    pub upd: cesr::Digest256,
    pub sea: cesr::Digest256,
}

/// SAIDs of the two events staged by a rotation helper.
#[derive(Debug, Clone)]
pub struct PeerSelRotationBatch {
    pub upd: cesr::Digest256,
    pub sea: cesr::Digest256,
}

/// Stage `[Icp, Upd, Sea]` on a fresh peer SEL chain and publish the
/// referenced SAD body via the supplied cascade. Generic over chain topic
/// + body so the same flow services both `peer/services` and `peer/gossip`.
///   The public wrappers select the topic.
async fn incept_peer_sel(
    builder: &mut SadEventBuilder,
    cascade: &dyn SadStore,
    peer_identity: cesr::Digest256,
    topic: &str,
    sad_said: cesr::Digest256,
    sad_body: &serde_json::Value,
) -> Result<PeerSelInceptionBatch, KelsError> {
    cascade.store(&sad_said, sad_body).await?;
    let (icp, upd) = builder.incept_chain(peer_identity, topic, sad_said).await?;
    let sea = builder.seal().await?;
    Ok(PeerSelInceptionBatch { icp, upd, sea })
}

/// Stage `[Upd, Sea]` extending an existing peer SEL chain and publish the
/// referenced SAD body via the cascade. The builder must be hydrated from
/// the chain's current tip (via `with_remote_prefix` / `with_prefix`).
async fn rotate_peer_sel(
    builder: &mut SadEventBuilder,
    cascade: &dyn SadStore,
    sad_said: cesr::Digest256,
    sad_body: &serde_json::Value,
) -> Result<PeerSelRotationBatch, KelsError> {
    cascade.store(&sad_said, sad_body).await?;
    let upd = builder.update(sad_said).await?;
    let sea = builder.seal().await?;
    Ok(PeerSelRotationBatch { upd, sea })
}

/// Stage an inception `[Icp, Upd, Sea]` for a peer's `peer/services` SEL,
/// publishing the [`PeerServicesSad`] body via the cascade.
///
/// KEL anchoring + `flush` remain the caller's responsibility — they must
/// happen in that order, with all three SAIDs anchored before submission.
/// Calling this helper is the only conforming way to author a fresh
/// `peer/services` chain: by construction the trailing `Sea` is always
/// staged, so no conforming caller can produce an Upd-tailed chain.
pub async fn incept_peer_services_sel(
    builder: &mut SadEventBuilder,
    cascade: &dyn SadStore,
    peer_identity: cesr::Digest256,
    sad: &PeerServicesSad,
) -> Result<PeerSelInceptionBatch, KelsError> {
    let body = serde_json::to_value(sad)?;
    incept_peer_sel(
        builder,
        cascade,
        peer_identity,
        PEER_SERVICES_SEL_TOPIC,
        sad.said,
        &body,
    )
    .await
}

/// Stage a rotation `[Upd, Sea]` on a peer's `peer/services` SEL,
/// publishing the new [`PeerServicesSad`] body via the cascade.
pub async fn rotate_peer_services_sel(
    builder: &mut SadEventBuilder,
    cascade: &dyn SadStore,
    sad: &PeerServicesSad,
) -> Result<PeerSelRotationBatch, KelsError> {
    let body = serde_json::to_value(sad)?;
    rotate_peer_sel(builder, cascade, sad.said, &body).await
}

/// Stage an inception `[Icp, Upd, Sea]` for a peer's `peer/gossip` SEL,
/// publishing the [`PeerGossipSad`] body via the cascade. The body is
/// `readPolicy`-gated at fetch time; the SAD store accepts the publish
/// unconditionally — gating fires on subsequent reads.
pub async fn incept_peer_gossip_sel(
    builder: &mut SadEventBuilder,
    cascade: &dyn SadStore,
    peer_identity: cesr::Digest256,
    sad: &PeerGossipSad,
) -> Result<PeerSelInceptionBatch, KelsError> {
    let body = serde_json::to_value(sad)?;
    incept_peer_sel(
        builder,
        cascade,
        peer_identity,
        PEER_GOSSIP_SEL_TOPIC,
        sad.said,
        &body,
    )
    .await
}

/// Stage a rotation `[Upd, Sea]` on a peer's `peer/gossip` SEL, publishing
/// the new [`PeerGossipSad`] body via the cascade.
pub async fn rotate_peer_gossip_sel(
    builder: &mut SadEventBuilder,
    cascade: &dyn SadStore,
    sad: &PeerGossipSad,
) -> Result<PeerSelRotationBatch, KelsError> {
    let body = serde_json::to_value(sad)?;
    rotate_peer_sel(builder, cascade, sad.said, &body).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    // ==================== PeerServicesSad shape ====================

    #[test]
    fn test_peer_services_sad_create_round_trip() {
        let sad = PeerServicesSad::create("node-a.example.net".to_string()).unwrap();
        assert_eq!(sad.domain, "node-a.example.net");
        assert!(sad.verify_said().is_ok());
    }

    #[test]
    fn test_peer_services_sad_said_changes_with_domain() {
        let a = PeerServicesSad::create("alice.example.net".to_string()).unwrap();
        let b = PeerServicesSad::create("bob.example.net".to_string()).unwrap();
        assert_ne!(a.said, b.said);
    }

    #[test]
    fn test_peer_services_sad_camel_case_serde() {
        let sad = PeerServicesSad::create("node-a.example.net".to_string()).unwrap();
        let json = serde_json::to_string(&sad).unwrap();
        assert!(json.contains("\"said\""));
        assert!(json.contains("\"domain\""));
    }

    // ==================== PeerGossipSad shape ====================

    #[test]
    fn test_peer_gossip_sad_create_round_trip() {
        let sad =
            PeerGossipSad::create(d(b"read-policy-said"), "203.0.113.4:4001".to_string()).unwrap();
        assert_eq!(sad.read_policy, d(b"read-policy-said"));
        assert_eq!(sad.address, "203.0.113.4:4001");
        assert!(sad.verify_said().is_ok());
    }

    #[test]
    fn test_peer_gossip_sad_said_changes_with_address() {
        let a = PeerGossipSad::create(d(b"read-policy"), "10.0.0.1:4001".to_string()).unwrap();
        let b = PeerGossipSad::create(d(b"read-policy"), "10.0.0.2:4001".to_string()).unwrap();
        assert_ne!(a.said, b.said);
    }

    #[test]
    fn test_peer_gossip_sad_camel_case_serde() {
        let sad =
            PeerGossipSad::create(d(b"read-policy-said"), "10.0.0.1:4001".to_string()).unwrap();
        let json = serde_json::to_string(&sad).unwrap();
        assert!(json.contains("\"said\""));
        assert!(json.contains("\"readPolicy\""));
        assert!(json.contains("\"address\""));
        assert!(!json.contains("read_policy"));
    }

    // ==================== Topics + prefix derivation ====================

    #[test]
    fn test_topic_constants() {
        assert_eq!(PEER_SERVICES_SEL_TOPIC, "kels/sel/v1/peer/services");
        assert_eq!(PEER_GOSSIP_SEL_TOPIC, "kels/sel/v1/peer/gossip");
    }

    #[test]
    fn test_compute_peer_services_sel_prefix_deterministic() {
        let peer = d(b"peer-identity");
        let p1 = compute_peer_services_sel_prefix(peer).unwrap();
        let p2 = compute_peer_services_sel_prefix(peer).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_compute_peer_gossip_sel_prefix_deterministic() {
        let peer = d(b"peer-identity");
        let p1 = compute_peer_gossip_sel_prefix(peer).unwrap();
        let p2 = compute_peer_gossip_sel_prefix(peer).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_compute_prefixes_differ_between_services_and_gossip() {
        // Different topics → different prefixes for the same peer identity.
        // Both chains coexist under the same peer identity without collision.
        let peer = d(b"peer-identity");
        let services_prefix = compute_peer_services_sel_prefix(peer).unwrap();
        let gossip_prefix = compute_peer_gossip_sel_prefix(peer).unwrap();
        assert_ne!(services_prefix, gossip_prefix);
    }

    #[test]
    fn test_compute_prefixes_differ_between_peers() {
        let alice = d(b"alice");
        let bob = d(b"bob");
        assert_ne!(
            compute_peer_services_sel_prefix(alice).unwrap(),
            compute_peer_services_sel_prefix(bob).unwrap()
        );
        assert_ne!(
            compute_peer_gossip_sel_prefix(alice).unwrap(),
            compute_peer_gossip_sel_prefix(bob).unwrap()
        );
    }

    #[test]
    fn test_compute_prefixes_match_general_sad_prefix() {
        // The dedicated helpers are thin specializations of
        // `compute_sad_event_prefix` with fixed topics — equivalence pins
        // that and surfaces drift if either side changes independently.
        let peer = d(b"peer-identity");
        assert_eq!(
            compute_peer_services_sel_prefix(peer).unwrap(),
            compute_sad_event_prefix(peer, PEER_SERVICES_SEL_TOPIC).unwrap()
        );
        assert_eq!(
            compute_peer_gossip_sel_prefix(peer).unwrap(),
            compute_sad_event_prefix(peer, PEER_GOSSIP_SEL_TOPIC).unwrap()
        );
    }
}
