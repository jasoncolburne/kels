//! Cryptographic primitives for the gossip network layer.
//!
//! Provides AES-GCM-256 session encryption and the [`EncryptedStream`] wrapper
//! that transparently encrypts/decrypts data flowing through a byte stream
//! (placed below yamux in the transport stack).

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, consts::U12},
};
use futures::{AsyncRead, AsyncWrite};
use pin_project_lite::pin_project;

/// Maximum plaintext frame size (64 KiB).
const MAX_FRAME_SIZE: usize = 64 * 1024;

/// AES-GCM tag length in bytes.
const TAG_LEN: usize = 16;

/// Frame length prefix size (4 bytes, big-endian).
const LEN_PREFIX_SIZE: usize = 4;

/// Derive two AES-256-GCM session keys from an ML-KEM shared secret.
///
/// Uses blake3's key derivation to produce separate keys for each direction,
/// incorporating both peer prefixes in the context for domain separation.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    our_prefix: &[u8; 44],
    their_prefix: &[u8; 44],
    is_initiator: bool,
) -> (Aes256Gcm, Aes256Gcm) {
    let (init_prefix, resp_prefix) = if is_initiator {
        (our_prefix, their_prefix)
    } else {
        (their_prefix, our_prefix)
    };

    let mut init_to_resp_context = b"kels/gossip/v1/keys/init-to-resp/".to_vec();
    init_to_resp_context.extend_from_slice(init_prefix);
    init_to_resp_context.extend_from_slice(resp_prefix);

    let mut resp_to_init_context = b"kels/gossip/v1/keys/resp-to-init/".to_vec();
    resp_to_init_context.extend_from_slice(init_prefix);
    resp_to_init_context.extend_from_slice(resp_prefix);

    let init_to_resp_key = blake3::derive_key(
        &String::from_utf8_lossy(&init_to_resp_context),
        shared_secret,
    );
    let resp_to_init_key = blake3::derive_key(
        &String::from_utf8_lossy(&resp_to_init_context),
        shared_secret,
    );

    let (send_key, recv_key) = if is_initiator {
        (init_to_resp_key, resp_to_init_key)
    } else {
        (resp_to_init_key, init_to_resp_key)
    };

    let send_cipher = Aes256Gcm::new(&send_key.into());
    let recv_cipher = Aes256Gcm::new(&recv_key.into());

    (send_cipher, recv_cipher)
}

/// Build a 12-byte AES-GCM nonce from a 64-bit counter.
///
/// Format: `[0x00, 0x00, 0x00, 0x00, counter_be_8bytes]`
fn nonce_from_counter(counter: u64) -> Nonce<U12> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce_bytes.into()
}

pin_project! {
    /// A stream wrapper that encrypts outgoing data and decrypts incoming data using AES-GCM-256.
    ///
    /// Each write produces one encrypted frame on the wire:
    /// ```text
    /// [4 bytes: ciphertext length (big-endian)] [ciphertext + 16-byte auth tag]
    /// ```
    ///
    /// Each direction uses a separate key and incrementing nonce counter, derived from the
    /// ML-KEM shared secret via [`derive_session_keys`].
    pub struct EncryptedStream<S> {
        #[pin]
        inner: S,
        send_cipher: Aes256Gcm,
        recv_cipher: Aes256Gcm,
        send_nonce: u64,
        recv_nonce: u64,
        // Read state
        read_plaintext: Vec<u8>,
        read_pos: usize,
        read_state: ReadState,
        // Write state
        write_state: WriteState,
    }
}

/// State machine for reading encrypted frames.
#[derive(Debug)]
enum ReadState {
    /// Reading the 4-byte length prefix.
    ReadingLength {
        buf: [u8; LEN_PREFIX_SIZE],
        pos: usize,
    },
    /// Reading the ciphertext body.
    ReadingBody { buf: Vec<u8>, pos: usize },
}

/// State machine for writing encrypted frames.
#[derive(Debug)]
enum WriteState {
    /// Ready to accept new data.
    Idle,
    /// Writing an encrypted frame to the inner stream.
    WritingFrame { frame: Vec<u8>, pos: usize },
}

impl<S> EncryptedStream<S> {
    /// Create a new encrypted stream.
    ///
    /// The `send_cipher` and `recv_cipher` should be derived from [`derive_session_keys`].
    pub fn new(inner: S, send_cipher: Aes256Gcm, recv_cipher: Aes256Gcm) -> Self {
        Self {
            inner,
            send_cipher,
            recv_cipher,
            send_nonce: 0,
            recv_nonce: 0,
            read_plaintext: Vec::new(),
            read_pos: 0,
            read_state: ReadState::ReadingLength {
                buf: [0u8; LEN_PREFIX_SIZE],
                pos: 0,
            },
            write_state: WriteState::Idle,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        // If we have buffered plaintext, return it first.
        if *this.read_pos < this.read_plaintext.len() {
            let available = &this.read_plaintext[*this.read_pos..];
            let n = buf.len().min(available.len());
            buf[..n].copy_from_slice(&available[..n]);
            *this.read_pos += n;
            // Reset buffer when fully consumed.
            if *this.read_pos >= this.read_plaintext.len() {
                this.read_plaintext.clear();
                *this.read_pos = 0;
            }
            return Poll::Ready(Ok(n));
        }

        // Read an encrypted frame from the inner stream.
        loop {
            match this.read_state {
                ReadState::ReadingLength { buf: len_buf, pos } => {
                    // Read the 4-byte length prefix.
                    while *pos < LEN_PREFIX_SIZE {
                        let inner = Pin::new(&mut *this.inner);
                        match inner.poll_read(cx, &mut len_buf[*pos..]) {
                            Poll::Ready(Ok(0)) => {
                                return if *pos == 0 {
                                    Poll::Ready(Ok(0)) // Clean EOF
                                } else {
                                    Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "EOF mid-frame header",
                                    )))
                                };
                            }
                            Poll::Ready(Ok(n)) => *pos += n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let frame_len = u32::from_be_bytes(*len_buf) as usize;
                    if frame_len > MAX_FRAME_SIZE + TAG_LEN {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "encrypted frame too large",
                        )));
                    }

                    *this.read_state = ReadState::ReadingBody {
                        buf: vec![0u8; frame_len],
                        pos: 0,
                    };
                }

                ReadState::ReadingBody {
                    buf: frame_buf,
                    pos,
                } => {
                    // Read the ciphertext body.
                    while *pos < frame_buf.len() {
                        let inner = Pin::new(&mut *this.inner);
                        match inner.poll_read(cx, &mut frame_buf[*pos..]) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF mid-frame body",
                                )));
                            }
                            Poll::Ready(Ok(n)) => *pos += n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Decrypt the frame.
                    let nonce = nonce_from_counter(*this.recv_nonce);
                    *this.recv_nonce += 1;

                    let plaintext = this
                        .recv_cipher
                        .decrypt(&nonce, frame_buf.as_ref())
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "decryption failed")
                        })?;

                    // Buffer the plaintext and return what the caller asked for.
                    let n = buf.len().min(plaintext.len());
                    buf[..n].copy_from_slice(&plaintext[..n]);

                    if n < plaintext.len() {
                        *this.read_plaintext = plaintext;
                        *this.read_pos = n;
                    }

                    // Reset to read next frame.
                    *this.read_state = ReadState::ReadingLength {
                        buf: [0u8; LEN_PREFIX_SIZE],
                        pos: 0,
                    };

                    return Poll::Ready(Ok(n));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        match this.write_state {
            WriteState::Idle => {
                // Limit frame size.
                let plaintext_len = buf.len().min(MAX_FRAME_SIZE);
                let plaintext = &buf[..plaintext_len];

                // Encrypt the data.
                let nonce = nonce_from_counter(*this.send_nonce);
                *this.send_nonce += 1;

                let ciphertext = this
                    .send_cipher
                    .encrypt(&nonce, plaintext)
                    .map_err(|_| io::Error::other("encryption failed"))?;

                // Build the frame: [length prefix][ciphertext + tag].
                let frame_len = ciphertext.len() as u32;
                let mut frame = Vec::with_capacity(LEN_PREFIX_SIZE + ciphertext.len());
                frame.extend_from_slice(&frame_len.to_be_bytes());
                frame.extend_from_slice(&ciphertext);

                // Try to write the frame.
                let inner = Pin::new(&mut *this.inner);
                match inner.poll_write(cx, &frame) {
                    Poll::Ready(Ok(n)) => {
                        if n >= frame.len() {
                            Poll::Ready(Ok(plaintext_len))
                        } else {
                            *this.write_state = WriteState::WritingFrame { frame, pos: n };
                            // We accepted the data, will flush the rest later.
                            Poll::Ready(Ok(plaintext_len))
                        }
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => {
                        *this.write_state = WriteState::WritingFrame { frame, pos: 0 };
                        Poll::Pending
                    }
                }
            }

            WriteState::WritingFrame { frame, pos, .. } => {
                // Continue writing the pending frame before accepting new data.
                let inner = Pin::new(&mut *this.inner);
                match inner.poll_write(cx, &frame[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        *pos += n;
                        if *pos >= frame.len() {
                            *this.write_state = WriteState::Idle;
                        }
                        // Re-poll to accept the new data now that we're idle.
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Flush any pending frame data first.
        if let WriteState::WritingFrame { frame, pos, .. } = this.write_state {
            while *pos < frame.len() {
                let inner = Pin::new(&mut *this.inner);
                match inner.poll_write(cx, &frame[*pos..]) {
                    Poll::Ready(Ok(n)) => *pos += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            *this.write_state = WriteState::Idle;
        }

        // Flush the inner stream.
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Flush any pending frame data first.
        if let WriteState::WritingFrame { frame, pos, .. } = this.write_state {
            while *pos < frame.len() {
                let inner = Pin::new(&mut *this.inner);
                match inner.poll_write(cx, &frame[*pos..]) {
                    Poll::Ready(Ok(n)) => *pos += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            *this.write_state = WriteState::Idle;
        }

        Pin::new(&mut *this.inner).poll_close(cx)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::time::Duration;

    use futures::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;

    #[tokio::test]
    async fn encrypted_stream_roundtrip() {
        let shared_secret = [0x42u8; 32];
        let init_prefix = [0x11u8; 44];
        let resp_prefix = [0x22u8; 44];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(|_| "accept failed")?;
            let compat = stream.compat();
            let (send_cipher, recv_cipher) =
                derive_session_keys(&shared_secret, &resp_prefix, &init_prefix, false);
            let mut encrypted = EncryptedStream::new(compat, send_cipher, recv_cipher);

            let mut buf = vec![0u8; 1024];
            let n = encrypted.read(&mut buf).await.map_err(|_| "read failed")?;
            encrypted
                .write_all(&buf[..n])
                .await
                .map_err(|_| "write failed")?;
            encrypted.flush().await.map_err(|_| "flush failed")?;
            Ok::<_, &str>(())
        });

        // Give the server a moment to start.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let stream = TcpStream::connect(addr).await.unwrap();
        let compat = stream.compat();
        let (send_cipher, recv_cipher) =
            derive_session_keys(&shared_secret, &init_prefix, &resp_prefix, true);
        let mut encrypted = EncryptedStream::new(compat, send_cipher, recv_cipher);

        let msg = b"hello encrypted world";
        encrypted.write_all(msg).await.unwrap();
        encrypted.flush().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = encrypted.read(&mut buf).await.unwrap();

        assert_eq!(&buf[..n], msg);

        let result = server.await;
        assert!(result.is_ok());
    }

    #[test]
    fn key_derivation_produces_different_keys() {
        let shared_secret = [0x42u8; 32];
        let init_prefix = [0x11u8; 44];
        let resp_prefix = [0x22u8; 44];

        let (send1, recv1) = derive_session_keys(&shared_secret, &init_prefix, &resp_prefix, true);
        let (send2, recv2) = derive_session_keys(&shared_secret, &resp_prefix, &init_prefix, false);

        // Initiator's send key should match acceptor's recv key.
        let nonce = nonce_from_counter(0);
        let plaintext = b"test";
        let ct1 = send1.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let pt2 = recv2.decrypt(&nonce, ct1.as_ref()).unwrap();
        assert_eq!(pt2, plaintext);

        // Acceptor's send key should match initiator's recv key.
        let ct2 = send2.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let pt1 = recv1.decrypt(&nonce, ct2.as_ref()).unwrap();
        assert_eq!(pt1, plaintext);
    }
}
