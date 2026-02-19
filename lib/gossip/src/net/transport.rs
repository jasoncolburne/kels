//! TCP transport with ECDH handshake and AES-GCM-256 encryption.
//!
//! Handles the full connection lifecycle:
//! 1. TCP connect/accept
//! 2. Prefix exchange (peer identity)
//! 3. ECDH key exchange (ephemeral P-256)
//! 4. Mutual authentication (sign and verify ephemeral keys)
//! 5. Derive AES-GCM-256 session keys and create encrypted stream

use std::net::SocketAddr;
use std::time::Duration;

use cesr::{KeyCode, Matter, PublicKey as CesrPublicKey};
use futures::{AsyncReadExt, AsyncWriteExt};
use serde::Serialize;
use socket2::SockRef;
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tracing::{debug, warn};

use crate::identity::NodePrefix;

use super::{
    Error, PeerVerifier, Signer, codec,
    crypto::{self, EncryptedStream},
};

/// JSON payload signed during the handshake.
///
/// Contains CESR-encoded ephemeral public keys and the peer's prefix.
/// Field order is deterministic via `serde_json` `preserve_order`.
#[derive(Serialize)]
struct HandshakePayload {
    our_eph: String,
    their_eph: String,
    their_prefix: String,
}

/// An established, authenticated, encrypted connection to a peer.
pub struct PeerConnection {
    /// The authenticated peer identity.
    pub peer_prefix: NodePrefix,
    /// The encrypted bidirectional stream.
    pub stream: EncryptedStream<Compat<TcpStream>>,
}

/// Perform the full handshake on an established TCP connection.
///
/// This implements the KELS gossip handshake protocol:
/// 1. Exchange prefixes (44 bytes each)
/// 2. ECDH ephemeral key exchange (33 bytes compressed P-256)
/// 3. Mutual authentication: each side signs a JSON payload containing CESR-encoded
///    ephemeral keys and the peer's prefix
/// 4. Verify peer's signature against their KEL public key
/// 5. Derive AES-GCM-256 session keys from the shared ECDH secret
///
/// Returns a `PeerConnection` with the authenticated peer identity and encrypted stream.
/// Configure TCP keepalive for faster stale connection detection.
///
/// Without this, a crashed peer's TCP connections linger for ~2 hours (default
/// OS keepalive). With these settings, dead connections are detected in ~25s.
fn configure_keepalive(tcp: &TcpStream) -> Result<(), Error> {
    let sock_ref = SockRef::from(tcp);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5));
    sock_ref.set_tcp_keepalive(&keepalive).map_err(Error::Io)
}

pub async fn handshake<S: Signer, V: PeerVerifier>(
    tcp: TcpStream,
    signer: &S,
    verifier: &V,
    is_initiator: bool,
) -> Result<PeerConnection, Error> {
    configure_keepalive(&tcp)?;
    let mut stream = tcp.compat();
    let our_id = signer.node_prefix();

    // Step 1: Exchange prefixes.
    let their_id = exchange_prefixes(&mut stream, &our_id, is_initiator).await?;
    debug!(peer = %their_id, "prefix exchange complete");

    // Step 2: ECDH key exchange (returns ephemeral SecretKey for static-ephemeral DH).
    let (ee_secret, eph_secret_key, our_eph, their_eph) =
        crypto::ecdh_key_exchange(&mut stream, is_initiator).await?;
    debug!(peer = %their_id, "ECDH key exchange complete");

    // Step 3: Sign our ephemeral key binding as a JSON payload.
    let sign_data = handshake_payload(&our_eph, &their_eph, &their_id)?;
    let sig_bundle = signer.sign(sign_data.as_bytes()).await?;

    // Exchange signatures and public keys.
    if is_initiator {
        codec::write_bytes(&mut stream, &sig_bundle.signature).await?;
        codec::write_bytes(&mut stream, &sig_bundle.public_key).await?;
    }

    let their_sig = codec::read_bytes(&mut stream).await?;
    let their_pubkey = codec::read_bytes(&mut stream).await?;

    if !is_initiator {
        codec::write_bytes(&mut stream, &sig_bundle.signature).await?;
        codec::write_bytes(&mut stream, &sig_bundle.public_key).await?;
    }

    // Step 4: Verify peer's signature.
    // They signed with our_eph/their_eph swapped (from their perspective).
    let verify_data = handshake_payload(&their_eph, &our_eph, &our_id)?;
    verifier
        .verify_peer(&their_id, verify_data.as_bytes(), &their_sig, &their_pubkey)
        .await?;
    debug!(peer = %their_id, "peer authentication verified");

    // Step 5: Static-ephemeral DH.
    // se: our_static × their_ephemeral (via identity service / HSM)
    let se_secret = signer.ecdh(&their_eph).await?;
    // es: our_ephemeral × their_static (local computation)
    let es_secret = crypto::compute_eph_static_dh(&eph_secret_key, &their_pubkey)?;

    // Step 6: Derive session keys from all three DH secrets.
    let (send_cipher, recv_cipher) =
        crypto::derive_session_keys(&ee_secret, &se_secret, &es_secret, is_initiator);
    let encrypted = EncryptedStream::new(stream, send_cipher, recv_cipher);

    Ok(PeerConnection {
        peer_prefix: their_id,
        stream: encrypted,
    })
}

/// Build the JSON string signed during the handshake.
///
/// CESR-encodes the ephemeral P-256 public keys and includes the peer prefix,
/// then serializes to a deterministic JSON string.
fn handshake_payload(
    our_eph: &[u8],
    their_eph: &[u8],
    their_id: &NodePrefix,
) -> Result<String, Error> {
    let our_eph_qb64 = CesrPublicKey::from_raw(KeyCode::Secp256r1, our_eph.to_vec())
        .map_err(|e| Error::Handshake(format!("CESR encode our_eph: {e}")))?
        .qb64();
    let their_eph_qb64 = CesrPublicKey::from_raw(KeyCode::Secp256r1, their_eph.to_vec())
        .map_err(|e| Error::Handshake(format!("CESR encode their_eph: {e}")))?
        .qb64();
    let their_prefix = their_id
        .to_option_string()
        .ok_or_else(|| Error::Handshake("Invalid peer prefix encoding".to_string()))?;

    let payload = HandshakePayload {
        our_eph: our_eph_qb64,
        their_eph: their_eph_qb64,
        their_prefix,
    };

    serde_json::to_string(&payload).map_err(|e| Error::Handshake(format!("JSON serialize: {e}")))
}

/// Exchange 44-byte prefixes between peers.
async fn exchange_prefixes<S: futures::AsyncRead + futures::AsyncWrite + Unpin>(
    stream: &mut S,
    our_id: &NodePrefix,
    is_initiator: bool,
) -> Result<NodePrefix, Error> {
    let mut their_bytes = [0u8; 44];

    if is_initiator {
        stream.write_all(&our_id.0).await?;
        stream.flush().await?;
        stream.read_exact(&mut their_bytes).await?;
    } else {
        stream.read_exact(&mut their_bytes).await?;
        stream.write_all(&our_id.0).await?;
        stream.flush().await?;
    }

    Ok(NodePrefix(their_bytes))
}

/// Dial a peer at the given address and perform the handshake.
pub async fn dial<S: Signer, V: PeerVerifier>(
    addr: SocketAddr,
    signer: &S,
    verifier: &V,
) -> Result<PeerConnection, Error> {
    debug!(%addr, "dialing peer");
    let tcp = TcpStream::connect(addr).await?;
    handshake(tcp, signer, verifier, true).await
}

/// Accept a connection from a TCP listener and perform the handshake.
pub async fn accept<S: Signer, V: PeerVerifier>(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    signer: &S,
    verifier: &V,
) -> Result<PeerConnection, Error> {
    debug!(%peer_addr, "accepting connection");
    match handshake(tcp, signer, verifier, false).await {
        Ok(conn) => {
            debug!(peer = %conn.peer_prefix, %peer_addr, "peer authenticated");
            Ok(conn)
        }
        Err(e) => {
            warn!(%peer_addr, error = %e, "handshake failed");
            Err(e)
        }
    }
}
