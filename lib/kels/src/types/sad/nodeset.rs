//! NodeSet — set of node prefixes for selective replication.
//!
//! #167: relocated from `custody.rs`. Stays a
//! separately-addressable [`SelfAddressed`] SAD referenced by SAID from
//! [`super::Availability::nodes`] (#167 factored `nodes` from custody to
//! availability). Storage and dedup behavior unchanged.
//!
//! Prefixes are sorted lexicographically before SAID derivation so the same
//! set of nodes always produces the same SAID regardless of insertion order.
//! Use [`NodeSet::create_sorted`] instead of `Self::create()` to ensure
//! correct ordering.

use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct NodeSet {
    #[said]
    pub said: cesr::Digest256,
    pub prefixes: Vec<cesr::Digest256>,
}

impl NodeSet {
    /// Create a NodeSet with prefixes sorted for deterministic SAID derivation.
    pub fn create_sorted(
        mut prefixes: Vec<cesr::Digest256>,
    ) -> Result<Self, verifiable_storage::StorageError> {
        prefixes.sort();
        Self::create(prefixes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    #[test]
    fn test_nodeset_create_sorted_deterministic() {
        let a = test_digest(b"node-a");
        let b = test_digest(b"node-b");
        let c = test_digest(b"node-c");

        let ns1 = NodeSet::create_sorted(vec![c, a, b]).unwrap();
        let ns2 = NodeSet::create_sorted(vec![b, c, a]).unwrap();
        let ns3 = NodeSet::create_sorted(vec![a, b, c]).unwrap();

        assert_eq!(ns1.said, ns2.said);
        assert_eq!(ns2.said, ns3.said);
        assert!(ns1.prefixes.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_nodeset_different_members_different_said() {
        let a = test_digest(b"node-a");
        let b = test_digest(b"node-b");

        let ns1 = NodeSet::create_sorted(vec![a, b]).unwrap();
        let ns2 = NodeSet::create_sorted(vec![a]).unwrap();
        assert_ne!(ns1.said, ns2.said);
    }

    #[test]
    fn test_nodeset_empty_is_valid() {
        let ns = NodeSet::create_sorted(vec![]).unwrap();
        assert!(ns.verify_said().is_ok());
    }
}
