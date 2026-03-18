//! TCP transport with handshake and AES-GCM-256 encryption.
//!
//! Handles the full connection lifecycle:
//! 1. TCP connect/accept
//! 2. Prefix exchange (peer identity)
//! 3. ML-KEM-768 key exchange and mutual ML-DSA-65 authentication
//! 4. Derive AES-GCM-256 session keys and create encrypted stream

use std::net::SocketAddr;
use std::time::Duration;

use cesr::{KemCiphertext, KemKeyCode, KemPublicKey, Matter, generate_ml_kem_768, generate_ml_kem_1024};
use futures::{AsyncReadExt, AsyncWriteExt};
use socket2::SockRef;
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tracing::{debug, warn};

use crate::identity::NodePrefix;

use super::{
    Error, PeerVerifier, SignatureBundle, Signer,
    crypto::{EncryptedStream, derive_session_keys},
};

/// An established, authenticated, encrypted connection to a peer.
pub struct PeerConnection {
    /// The authenticated peer identity.
    pub peer_prefix: NodePrefix,
    /// The encrypted bidirectional stream.
    pub stream: EncryptedStream<Compat<TcpStream>>,
}

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

    // Step 2: ML-KEM key exchange.
    let kem_algo = signer.kem_algorithm();
    let (shared_secret, our_ek_qb64, their_ek_qb64) =
        mlkem_key_exchange(&mut stream, is_initiator, kem_algo).await?;
    debug!(peer = %their_id, "ML-KEM key exchange complete");

    // Step 3: Sign handshake transcript.
    let payload = handshake_payload(&our_ek_qb64, &their_ek_qb64, &their_id);
    let our_sig = signer.sign(payload.as_bytes()).await?;

    // Step 4: Exchange and verify signatures.
    let their_sig = exchange_signatures(&mut stream, &our_sig, is_initiator).await?;

    // Verify peer's signature (they signed with our_ek and their_ek swapped, and our prefix)
    let their_payload = handshake_payload(&their_ek_qb64, &our_ek_qb64, &our_id);
    verifier
        .verify_peer(
            &their_id,
            their_payload.as_bytes(),
            &their_sig.signature,
            &their_sig.public_key,
        )
        .await
        .map_err(|e| Error::Handshake(format!("Peer verification failed: {}", e)))?;
    debug!(peer = %their_id, "peer authenticated");

    // Step 5: Derive session keys from ML-KEM shared secret.
    let (send_cipher, recv_cipher) =
        derive_session_keys(&shared_secret, &our_id.0, &their_id.0, is_initiator);
    let encrypted = EncryptedStream::new(stream, send_cipher, recv_cipher);

    Ok(PeerConnection {
        peer_prefix: their_id,
        stream: encrypted,
    })
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

/// Perform ML-KEM key exchange (ML-KEM-768 or ML-KEM-1024).
///
/// Returns (shared_secret, our_ek_or_ct_qb64, their_ek_or_ct_qb64).
/// - Initiator: generates keypair, sends ek, receives ct, decapsulates.
/// - Acceptor: receives ek, encapsulates, sends ct (auto-detects algorithm from received ek).
async fn mlkem_key_exchange<S: futures::AsyncRead + futures::AsyncWrite + Unpin>(
    stream: &mut S,
    is_initiator: bool,
    kem_algo: KemKeyCode,
) -> Result<([u8; 32], String, String), Error> {
    if is_initiator {
        // Generate ML-KEM keypair
        let (ek, dk) = match kem_algo {
            KemKeyCode::MlKem768 => generate_ml_kem_768(),
            KemKeyCode::MlKem1024 => generate_ml_kem_1024(),
        }
        .map_err(|e| Error::Handshake(format!("ML-KEM keygen failed: {}", e)))?;
        let ek_qb64 = ek.qb64();

        // Send encapsulation key
        send_length_prefixed(stream, ek_qb64.as_bytes()).await?;

        // Receive ciphertext
        let ct_bytes = recv_length_prefixed(stream).await?;
        let ct_qb64 = String::from_utf8(ct_bytes)
            .map_err(|_| Error::Handshake("Invalid ciphertext encoding".into()))?;
        let ct = KemCiphertext::from_qb64(&ct_qb64)
            .map_err(|e| Error::Handshake(format!("Invalid ciphertext: {}", e)))?;

        // Decapsulate
        let shared_secret = dk
            .decapsulate(&ct)
            .map_err(|e| Error::Handshake(format!("Decapsulation failed: {}", e)))?;

        Ok((shared_secret, ek_qb64, ct_qb64))
    } else {
        // Receive encapsulation key
        let ek_bytes = recv_length_prefixed(stream).await?;
        let ek_qb64 = String::from_utf8(ek_bytes)
            .map_err(|_| Error::Handshake("Invalid encapsulation key encoding".into()))?;
        let ek = KemPublicKey::from_qb64(&ek_qb64)
            .map_err(|e| Error::Handshake(format!("Invalid encapsulation key: {}", e)))?;

        // Encapsulate
        let (ct, shared_secret) = ek
            .encapsulate()
            .map_err(|e| Error::Handshake(format!("Encapsulation failed: {}", e)))?;
        let ct_qb64 = ct.qb64();

        // Send ciphertext
        send_length_prefixed(stream, ct_qb64.as_bytes()).await?;

        Ok((shared_secret, ct_qb64, ek_qb64))
    }
}

/// Exchange ML-DSA-65 signature bundles between peers.
async fn exchange_signatures<S: futures::AsyncRead + futures::AsyncWrite + Unpin>(
    stream: &mut S,
    our_sig: &SignatureBundle,
    is_initiator: bool,
) -> Result<SignatureBundle, Error> {
    // Serialize our bundle: 4-byte sig_len + sig + 4-byte key_len + key
    let mut our_payload = Vec::new();
    our_payload.extend_from_slice(&(our_sig.signature.len() as u32).to_be_bytes());
    our_payload.extend_from_slice(&our_sig.signature);
    our_payload.extend_from_slice(&(our_sig.public_key.len() as u32).to_be_bytes());
    our_payload.extend_from_slice(&our_sig.public_key);

    if is_initiator {
        send_length_prefixed(stream, &our_payload).await?;
        let their_payload = recv_length_prefixed(stream).await?;
        deserialize_signature_bundle(&their_payload)
    } else {
        let their_payload = recv_length_prefixed(stream).await?;
        send_length_prefixed(stream, &our_payload).await?;
        deserialize_signature_bundle(&their_payload)
    }
}

fn deserialize_signature_bundle(data: &[u8]) -> Result<SignatureBundle, Error> {
    if data.len() < 8 {
        return Err(Error::Handshake("Signature bundle too short".into()));
    }

    let sig_len = u32::from_be_bytes(
        data[..4]
            .try_into()
            .map_err(|_| Error::Handshake("bad sig len".into()))?,
    ) as usize;
    if data.len() < 4 + sig_len + 4 {
        return Err(Error::Handshake("Signature bundle truncated".into()));
    }

    let signature = data[4..4 + sig_len].to_vec();
    let key_offset = 4 + sig_len;
    let key_len = u32::from_be_bytes(
        data[key_offset..key_offset + 4]
            .try_into()
            .map_err(|_| Error::Handshake("bad key len".into()))?,
    ) as usize;
    if data.len() < key_offset + 4 + key_len {
        return Err(Error::Handshake("Signature bundle key truncated".into()));
    }

    let public_key = data[key_offset + 4..key_offset + 4 + key_len].to_vec();

    Ok(SignatureBundle {
        signature,
        public_key,
    })
}

/// Build the JSON handshake payload that each side signs.
fn handshake_payload(our_ek: &str, their_ek: &str, their_prefix: &NodePrefix) -> String {
    serde_json::json!({
        "our_ek": our_ek,
        "their_ek": their_ek,
        "their_prefix": hex::encode(their_prefix.0),
    })
    .to_string()
}

/// Send a length-prefixed message (4-byte big-endian length + payload).
async fn send_length_prefixed<S: futures::AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> Result<(), Error> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Maximum handshake message size (8 KiB — larger than any single ML-KEM/ML-DSA artifact).
const MAX_HANDSHAKE_MSG: usize = 8 * 1024;

/// Receive a length-prefixed message (4-byte big-endian length + payload).
async fn recv_length_prefixed<S: futures::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HANDSHAKE_MSG {
        return Err(Error::Handshake(format!(
            "Handshake message too large: {} bytes",
            len
        )));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
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
