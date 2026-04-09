//! `kels://` URI scheme for peer addressing.
//!
//! Peer addresses use the format `kels://prefix@host:port`:
//! - `kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@192.168.1.1:4001` (IPv4)
//! - `kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@gossip.example.com:4001` (DNS)
//! - `kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@[::1]:4001` (IPv6)
//!
//! CESR Base64 uses URL-safe characters (`A-Za-z0-9-_`), so the prefix is valid in URI
//! userinfo without escaping.

use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};

use cesr::Matter;

/// A parsed `kels://` peer address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAddr {
    /// The peer's KELS prefix (CESR digest).
    pub prefix: cesr::Digest,
    /// The host (IPv4, IPv6, or DNS name).
    pub host: String,
    /// The port number.
    pub port: u16,
}

/// Error type for `kels://` URI parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrError {
    /// URI does not start with `kels://`.
    InvalidScheme,
    /// Missing `@` separator between prefix and host.
    MissingPrefix,
    /// Prefix is not a valid 44-character CESR identifier.
    InvalidPrefix,
    /// Missing `:port` in the address.
    MissingPort,
    /// Port is not a valid number.
    InvalidPort,
    /// Address format is invalid.
    InvalidAddress,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrError::InvalidScheme => write!(f, "URI must start with kels://"),
            AddrError::MissingPrefix => write!(f, "missing prefix@ in URI"),
            AddrError::InvalidPrefix => write!(f, "invalid 44-character CESR prefix"),
            AddrError::MissingPort => write!(f, "missing :port in address"),
            AddrError::InvalidPort => write!(f, "invalid port number"),
            AddrError::InvalidAddress => write!(f, "invalid address format"),
        }
    }
}

impl std::error::Error for AddrError {}

impl PeerAddr {
    /// Parse a `kels://prefix@host:port` URI.
    pub fn parse(uri: &str) -> Result<Self, AddrError> {
        let stripped = uri
            .strip_prefix("kels://")
            .ok_or(AddrError::InvalidScheme)?;
        let (prefix_str, rest) = stripped.split_once('@').ok_or(AddrError::MissingPrefix)?;

        let prefix = cesr::Digest::from_qb64(prefix_str).map_err(|_| AddrError::InvalidPrefix)?;

        // Handle IPv6 bracket notation: [::1]:port
        let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
            let bracket_end = bracketed.find(']').ok_or(AddrError::InvalidAddress)?;
            let host = &bracketed[..bracket_end];
            let port_str = bracketed[bracket_end + 1..]
                .strip_prefix(':')
                .ok_or(AddrError::MissingPort)?;
            let port = port_str.parse().map_err(|_| AddrError::InvalidPort)?;
            (host.to_string(), port)
        } else {
            let (host, port_str) = rest.rsplit_once(':').ok_or(AddrError::MissingPort)?;
            let port = port_str.parse().map_err(|_| AddrError::InvalidPort)?;
            (host.to_string(), port)
        };

        Ok(PeerAddr { prefix, host, port })
    }

    /// Format as a `kels://` URI.
    pub fn to_uri(&self) -> String {
        let prefix = self.prefix.to_string();
        if self.host.contains(':') {
            // IPv6 — wrap in brackets
            format!("kels://{prefix}@[{}]:{}", self.host, self.port)
        } else {
            format!("kels://{prefix}@{}:{}", self.host, self.port)
        }
    }

    /// Resolve the address to a `SocketAddr`.
    ///
    /// Performs DNS resolution if the host is a domain name.
    pub fn to_socket_addr(&self) -> Result<SocketAddr, std::io::Error> {
        let addr_str = format!("{}:{}", self.host, self.port);
        addr_str
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::other("DNS resolution returned no addresses"))
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_uri())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_prefix() -> cesr::Digest {
        cesr::Digest::from_qb64("KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a").unwrap()
    }

    #[test]
    fn parse_ipv4() {
        let addr =
            PeerAddr::parse("kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@192.168.1.1:4001")
                .unwrap();
        assert_eq!(addr.prefix, test_prefix());
        assert_eq!(addr.host, "192.168.1.1");
        assert_eq!(addr.port, 4001);
    }

    #[test]
    fn parse_dns() {
        let addr = PeerAddr::parse(
            "kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@gossip.example.com:4001",
        )
        .unwrap();
        assert_eq!(addr.host, "gossip.example.com");
        assert_eq!(addr.port, 4001);
    }

    #[test]
    fn parse_ipv6() {
        let addr =
            PeerAddr::parse("kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@[::1]:4001")
                .unwrap();
        assert_eq!(addr.host, "::1");
        assert_eq!(addr.port, 4001);
    }

    #[test]
    fn roundtrip() {
        let original = "kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@192.168.1.1:4001";
        let addr = PeerAddr::parse(original).unwrap();
        assert_eq!(addr.to_uri(), original);
    }

    #[test]
    fn roundtrip_ipv6() {
        let original = "kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@[::1]:4001";
        let addr = PeerAddr::parse(original).unwrap();
        assert_eq!(addr.to_uri(), original);
    }

    #[test]
    fn invalid_scheme() {
        assert_eq!(
            PeerAddr::parse("http://prefix@host:4001"),
            Err(AddrError::InvalidScheme)
        );
    }

    #[test]
    fn missing_prefix() {
        assert_eq!(
            PeerAddr::parse("kels://host:4001"),
            Err(AddrError::MissingPrefix)
        );
    }

    #[test]
    fn missing_port() {
        assert_eq!(
            PeerAddr::parse("kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@host"),
            Err(AddrError::MissingPort)
        );
    }

    #[test]
    fn resolve_localhost() {
        let addr =
            PeerAddr::parse("kels://KBfxc4RiVY6saIFmUfEtU99OdZMN-TFLV2_oCIAeiY_a@127.0.0.1:4001")
                .unwrap();
        let socket_addr = addr.to_socket_addr().unwrap();
        assert_eq!(socket_addr.port(), 4001);
    }
}
