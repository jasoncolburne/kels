//! Per-peer address SAD + SEL topic.
//!
//! The federation IEL holds *who* is authorized. The per-peer **address SEL**
//! — a SAD Event Log rooted at each peer's own identity, at a deterministic
//! prefix — holds *where* to reach them. The current address is the SAD body
//! referenced by the latest accepted `Upd` on that chain.
//!
//! - SEL topic: [`ADDRESS_SEL_TOPIC`] (`"kels/sel/v1/peer/addresses"`).
//! - SEL prefix: [`compute_address_sel_prefix`] = `compute_sad_event_prefix(peer_identity, ADDRESS_SEL_TOPIC)`.
//! - SAD body: [`AddressSad`] — `{ said, readPolicy, endpoints }`, fetch-gated by `readPolicy`.
//!
//! Design: `docs/design/infrastructure/federation.md §Per-peer address publication`,
//! `docs/design/infrastructure/discovery.md`, `docs/design/infrastructure/peer-identity.md`.

use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

use crate::{
    SadEventBuilder, error::KelsError, store::sad::SadStore,
    types::sad::compute_sad_event_prefix,
};

/// SEL chain topic for per-peer address publication. Embedded in the chain's
/// `topic` field at `Icp` and participates in chain-prefix derivation alongside
/// the peer identity prefix — see [`compute_address_sel_prefix`]. The same
/// string is re-exported as `SEL_TOPIC` by `services/gossip/src/gossip_layer.rs`
/// for use by the discovery walker.
pub const ADDRESS_SEL_TOPIC: &str = "kels/sel/v1/peer/addresses";

/// One published network endpoint for a peer.
///
/// `address` is a TCP gossip endpoint expressed as `host:port` (IPv4, IPv6 in
/// bracketed form, or hostname). Gossip carries its own transport
/// (ML-KEM-1024 + ML-DSA + AES-GCM-256); only the network endpoint travels in
/// this field.
///
/// `region` is optional, opaque, free-form (e.g. `"us-east"`). Absence is
/// meaningful — the peer chose not to tag a region. Latency-aware clients may
/// prefer in-region endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub region: Option<String>,
}

/// Address SAD — the body published per address-SEL `Upd`.
///
/// Schema per `docs/design/infrastructure/federation.md §Address SAD schema`:
///
/// ```json
/// {
///   "said": "K...",
///   "readPolicy": "K...",
///   "endpoints": [
///     { "address": "203.0.113.4:4001", "region": "us-east" },
///     { "address": "[2001:db8::4]:4001" }
///   ]
/// }
/// ```
///
/// `readPolicy` is the SAID of a policy SAD whose expression is
/// `iel(FEDERATION_IEL_PREFIX)`. The sadstore evaluates it at fetch time via
/// `evaluate_signed_policy` against the request's verified prefix set — only
/// peers currently in the federation `authPolicy` can read the body. The SEL
/// chain itself (`Icp` / `Upd` / `Sea`) is public per `sadstore.md §Custody`;
/// only the SAD body is gated.
///
/// There is no `role` field by design — capabilities derive from the federation
/// IEL, not from peer self-declaration.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct AddressSad {
    #[said]
    pub said: cesr::Digest256,
    /// SAID of the policy SAD gating fetch access.
    pub read_policy: cesr::Digest256,
    /// Published endpoints, in publisher-chosen order. Multi-address is
    /// first-class — peers commonly publish IPv4/IPv6 pairs, regional
    /// alternates, or transitional endpoints during migration.
    pub endpoints: Vec<Endpoint>,
}

/// Compute the deterministic address-SEL prefix for a peer identity.
///
/// Wraps [`compute_sad_event_prefix`] with the fixed [`ADDRESS_SEL_TOPIC`]. Any
/// node can call this offline; given the peer's identity prefix (which the
/// federation IEL's `authPolicy` lists), the address SEL prefix is recoverable
/// without a directory service or registry lookup.
pub fn compute_address_sel_prefix(
    peer_identity: cesr::Digest256,
) -> Result<cesr::Digest256, KelsError> {
    compute_sad_event_prefix(peer_identity, ADDRESS_SEL_TOPIC)
}

/// SAIDs of the three events staged by [`incept_address_sel`].
///
/// Returned so the caller can anchor each SAID in the peer-identity KEL
/// before calling [`SadEventBuilder::flush`] — the SEL submit handler's
/// anchor checks fire against the IEL-resolved `authPolicy` /
/// `governancePolicy`.
#[derive(Debug, Clone)]
pub struct AddressSelInceptionBatch {
    pub icp: cesr::Digest256,
    pub upd: cesr::Digest256,
    pub sea: cesr::Digest256,
}

/// SAIDs of the two events staged by [`rotate_address_sel`].
#[derive(Debug, Clone)]
pub struct AddressSelRotationBatch {
    pub upd: cesr::Digest256,
    pub sea: cesr::Digest256,
}

/// Stage an address-SEL inception (`[Icp, Upd, Sea]`) and publish the
/// referenced [`AddressSad`] body via the supplied cascade.
///
/// Operation order:
///
/// 1. `cascade.store(address_sad.said, body)` — fans the body out to every
///    cascade layer (local cache + remote sadstore). The body must be
///    fetchable by the remote sadstore before any SEL event references its
///    SAID — the submit handler's content-existence check rejects SEL Upd
///    events whose content is unknown.
/// 2. `builder.incept_chain(peer_identity, ADDRESS_SEL_TOPIC, address_sad.said)` —
///    stages `[Icp, Upd]` with the SAD's SAID as the Upd's content.
/// 3. `builder.seal()` — stages the trailing `Sea`, satisfying the
///    Sea-after-Upd ratchet so the chain is sealed at every publication
///    boundary.
///
/// The helper **does not** call [`SadEventBuilder::flush`]. Anchoring the
/// returned SAIDs in the peer-identity KEL and calling `flush()` are the
/// caller's responsibility — they must happen in that order, with all three
/// SAIDs anchored before the batch is submitted.
///
/// Tooling that wants to author a fresh address SEL **must** call this helper
/// rather than the lower-level `incept_chain` / `seal` pair. The helper is
/// the federation address-SEL convention's enforcement point: a partial
/// staging (Icp + Upd without Sea) cannot be expressed through this API, so
/// no conforming caller can produce an Upd-tailed address SEL chain.
pub async fn incept_address_sel(
    builder: &mut SadEventBuilder,
    cascade: &dyn SadStore,
    peer_identity: cesr::Digest256,
    address_sad: &AddressSad,
) -> Result<AddressSelInceptionBatch, KelsError> {
    let body = serde_json::to_value(address_sad)?;
    cascade.store(&address_sad.said, &body).await?;

    let (icp, upd) = builder
        .incept_chain(peer_identity, ADDRESS_SEL_TOPIC, address_sad.said)
        .await?;
    let sea = builder.seal().await?;
    Ok(AddressSelInceptionBatch { icp, upd, sea })
}

/// Stage an address-SEL rotation (`[Upd, Sea]`) and publish the referenced
/// [`AddressSad`] body via the supplied cascade.
///
/// Same shape as [`incept_address_sel`] but extends an existing chain (the
/// `builder` must be hydrated from the peer's current SEL tip via
/// `with_remote_prefix` / `with_prefix`). Operation order:
///
/// 1. `cascade.store(address_sad.said, body)`.
/// 2. `builder.update(address_sad.said)` — stages the new `Upd`.
/// 3. `builder.seal()` — stages the trailing `Sea`.
///
/// `flush` and KEL anchoring remain the caller's responsibility, same as in
/// [`incept_address_sel`].
pub async fn rotate_address_sel(
    builder: &mut SadEventBuilder,
    cascade: &dyn SadStore,
    address_sad: &AddressSad,
) -> Result<AddressSelRotationBatch, KelsError> {
    let body = serde_json::to_value(address_sad)?;
    cascade.store(&address_sad.said, &body).await?;

    let upd = builder.update(address_sad.said).await?;
    let sea = builder.seal().await?;
    Ok(AddressSelRotationBatch { upd, sea })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    // ==================== AddressSad shape ====================

    #[test]
    fn test_address_sad_create_round_trip() {
        let endpoints = vec![
            Endpoint {
                address: "203.0.113.4:4001".to_string(),
                region: Some("us-east".to_string()),
            },
            Endpoint {
                address: "[2001:db8::4]:4001".to_string(),
                region: None,
            },
        ];
        let sad = AddressSad::create(d(b"read-policy-said"), endpoints.clone()).unwrap();
        assert_eq!(sad.read_policy, d(b"read-policy-said"));
        assert_eq!(sad.endpoints, endpoints);
        assert!(sad.verify_said().is_ok());
    }

    #[test]
    fn test_address_sad_said_changes_with_endpoints() {
        let read_policy = d(b"read-policy-said");
        let sad_a = AddressSad::create(
            read_policy,
            vec![Endpoint {
                address: "10.0.0.1:4001".to_string(),
                region: None,
            }],
        )
        .unwrap();
        let sad_b = AddressSad::create(
            read_policy,
            vec![Endpoint {
                address: "10.0.0.2:4001".to_string(),
                region: None,
            }],
        )
        .unwrap();
        assert_ne!(sad_a.said, sad_b.said);
    }

    #[test]
    fn test_address_sad_said_changes_with_endpoint_order() {
        // Endpoint order matters — endpoints is `Vec<Endpoint>`, not a set.
        // Publishers choose order; SAID reflects it. (Contrast NodeSet, which
        // sorts before SAID derivation because the *set* is the identity.)
        let read_policy = d(b"read-policy-said");
        let a = Endpoint {
            address: "10.0.0.1:4001".to_string(),
            region: None,
        };
        let b = Endpoint {
            address: "10.0.0.2:4001".to_string(),
            region: None,
        };
        let sad_ab = AddressSad::create(read_policy, vec![a.clone(), b.clone()]).unwrap();
        let sad_ba = AddressSad::create(read_policy, vec![b, a]).unwrap();
        assert_ne!(sad_ab.said, sad_ba.said);
    }

    #[test]
    fn test_address_sad_said_changes_with_region() {
        let read_policy = d(b"read-policy-said");
        let sad_tagged = AddressSad::create(
            read_policy,
            vec![Endpoint {
                address: "10.0.0.1:4001".to_string(),
                region: Some("us-east".to_string()),
            }],
        )
        .unwrap();
        let sad_untagged = AddressSad::create(
            read_policy,
            vec![Endpoint {
                address: "10.0.0.1:4001".to_string(),
                region: None,
            }],
        )
        .unwrap();
        assert_ne!(sad_tagged.said, sad_untagged.said);
    }

    #[test]
    fn test_address_sad_camel_case_serde() {
        let sad = AddressSad::create(
            d(b"read-policy-said"),
            vec![Endpoint {
                address: "10.0.0.1:4001".to_string(),
                region: Some("us-east".to_string()),
            }],
        )
        .unwrap();
        let json = serde_json::to_string(&sad).unwrap();
        assert!(json.contains("\"readPolicy\""));
        assert!(json.contains("\"endpoints\""));
        assert!(json.contains("\"address\""));
        assert!(json.contains("\"region\""));
        assert!(!json.contains("read_policy"));
    }

    #[test]
    fn test_endpoint_region_skipped_when_absent() {
        let endpoint = Endpoint {
            address: "10.0.0.1:4001".to_string(),
            region: None,
        };
        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(!json.contains("region"));
    }

    #[test]
    fn test_address_sad_empty_endpoints_valid_but_meaningful() {
        // An empty endpoints list is structurally valid (peer publishing
        // "no addresses currently" — e.g., a node preparing to be removed
        // gracefully). SAID-verifies. Application-layer concerns about
        // discoverability are not enforced at the type boundary.
        let sad = AddressSad::create(d(b"read-policy-said"), vec![]).unwrap();
        assert!(sad.verify_said().is_ok());
        assert!(sad.endpoints.is_empty());
    }

    // ==================== Prefix derivation ====================

    #[test]
    fn test_address_sel_topic_constant() {
        assert_eq!(ADDRESS_SEL_TOPIC, "kels/sel/v1/peer/addresses");
    }

    #[test]
    fn test_compute_address_sel_prefix_deterministic() {
        let peer = d(b"peer-identity");
        let p1 = compute_address_sel_prefix(peer).unwrap();
        let p2 = compute_address_sel_prefix(peer).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_compute_address_sel_prefix_differs_by_peer() {
        let p_alice = compute_address_sel_prefix(d(b"alice")).unwrap();
        let p_bob = compute_address_sel_prefix(d(b"bob")).unwrap();
        assert_ne!(p_alice, p_bob);
    }

    #[test]
    fn test_compute_address_sel_prefix_matches_general_sad_prefix() {
        // The address-SEL prefix wrapper is a thin specialization of
        // `compute_sad_event_prefix` with the fixed topic — equivalence
        // here pins that and surfaces drift if either side ever changes
        // independently.
        let peer = d(b"peer-identity");
        let wrapped = compute_address_sel_prefix(peer).unwrap();
        let general = compute_sad_event_prefix(peer, ADDRESS_SEL_TOPIC).unwrap();
        assert_eq!(wrapped, general);
    }
}
