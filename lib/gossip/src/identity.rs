//! Peer identity for the KELS gossip protocol.
//!
//! In KELS, peer identity is a 44-character CESR-encoded Blake3 hash (the KELS prefix).
//! This module provides the [`NodePrefix`] type that satisfies the protocol's [`PeerPrefixentity`]
//! trait requirements (Hash, Eq, Ord, Copy, Debug, Serialize, Deserialize).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A peer's identity in the KELS gossip network.
///
/// This is a KELS prefix: a 44-byte CESR-encoded Blake3-256 hash that uniquely identifies
/// a peer's Key Event Log. The prefix is derived from the inception event and remains stable
/// across the entire chain lifetime.
///
/// The 44 bytes are the raw UTF-8 bytes of the CESR qb64 string (e.g.,
/// `KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a`). CESR Base64 uses URL-safe characters
/// (`A-Za-z0-9-_`), so every byte is a valid ASCII character.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodePrefix(pub [u8; 44]);

impl Serialize for NodePrefix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(44)?;
        for byte in &self.0 {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for NodePrefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{self, SeqAccess, Visitor};

        struct NodePrefixVisitor;
        impl<'de> Visitor<'de> for NodePrefixVisitor {
            type Value = NodePrefix;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 44-byte array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NodePrefix, A::Error> {
                let mut arr = [0u8; 44];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(NodePrefix(arr))
            }
        }
        deserializer.deserialize_tuple(44, NodePrefixVisitor)
    }
}

impl NodePrefix {
    /// Create a `NodePrefix` from a 44-byte array.
    pub const fn from_bytes(bytes: [u8; 44]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 44] {
        &self.0
    }

    /// Convert to a CESR prefix string.
    ///
    /// Returns `None` if the bytes are not valid UTF-8 (should not happen for valid CESR).
    pub fn to_option_string(&self) -> Option<String> {
        std::str::from_utf8(&self.0).ok().map(|s| s.to_string())
    }

    /// Create a `NodePrefix` from a CESR prefix string.
    ///
    /// Returns `None` if the string is not exactly 44 bytes.
    pub fn option_from_str(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != 44 {
            return None;
        }
        let mut arr = [0u8; 44];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }
}

impl fmt::Debug for NodePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match std::str::from_utf8(&self.0) {
            Ok(s) => write!(f, "NodePrefix({}..{})", &s[..4], &s[40..]),
            Err(_) => write!(f, "NodePrefix(<invalid utf8>)"),
        }
    }
}

impl fmt::Display for NodePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match std::str::from_utf8(&self.0) {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "<invalid>"),
        }
    }
}

impl AsRef<[u8]> for NodePrefix {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 44]> for NodePrefix {
    fn as_ref(&self) -> &[u8; 44] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_prefix_from_prefix_str() {
        let prefix = "KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a";
        assert_eq!(prefix.len(), 44);
        let node_prefix = NodePrefix::option_from_str(prefix);
        assert!(node_prefix.is_some());
        let node_prefix = node_prefix.unwrap_or_else(|| NodePrefix::from_bytes([0; 44]));
        assert_eq!(node_prefix.to_option_string().as_deref(), Some(prefix));
    }

    #[test]
    fn node_prefix_too_short() {
        assert!(NodePrefix::option_from_str("too_short").is_none());
    }

    #[test]
    fn node_prefix_too_long() {
        let long = "A".repeat(45);
        assert!(NodePrefix::option_from_str(&long).is_none());
    }

    #[test]
    fn node_prefix_debug_format() {
        let prefix = "KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a";
        let node_prefix =
            NodePrefix::option_from_str(prefix).unwrap_or_else(|| NodePrefix::from_bytes([0; 44]));
        let debug = format!("{node_prefix:?}");
        assert!(debug.starts_with("NodePrefix(KBfx"));
        assert!(debug.ends_with("Y_a)"));
    }

    #[test]
    fn node_prefix_display_format() {
        let prefix = "KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a";
        let node_prefix =
            NodePrefix::option_from_str(prefix).unwrap_or_else(|| NodePrefix::from_bytes([0; 44]));
        assert_eq!(format!("{node_prefix}"), prefix);
    }

    #[test]
    fn node_prefix_copy_and_eq() {
        let a = NodePrefix::from_bytes([b'A'; 44]);
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn node_prefix_ord() {
        let a = NodePrefix::from_bytes([b'A'; 44]);
        let b = NodePrefix::from_bytes([b'B'; 44]);
        assert!(a < b);
    }

    #[test]
    fn node_prefix_serde_roundtrip() {
        let prefix = "KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a";
        let node_prefix =
            NodePrefix::option_from_str(prefix).unwrap_or_else(|| NodePrefix::from_bytes([0; 44]));
        let serialized = postcard::to_stdvec(&node_prefix);
        assert!(serialized.is_ok());
        if let Ok(bytes) = serialized {
            let deserialized: Result<NodePrefix, _> = postcard::from_bytes(&bytes);
            assert!(deserialized.is_ok());
            if let Ok(restored) = deserialized {
                assert_eq!(restored, node_prefix);
            }
        }
    }
}
